import Foundation
import Testing
import AnisetteKit
@testable import SideSign

// Every request is intercepted. These tests never contact Apple or an anisette server.
final class AnisetteAuthURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var requests: [URLRequest] = []
    nonisolated(unsafe) static var rejectBlob = false
    nonisolated(unsafe) static var emptyIdentity = false
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        Self.lock.withLock { Self.requests.append(request) }
        let path = request.url!.path
        var status = 200
        let data: Data
        if path == "/v3/client_info" {
            data = try! JSONSerialization.data(withJSONObject: [
                "client_info": Self.emptyIdentity ? "" : "WINDOWS_SERVER_IDENTITY",
                "user_agent": "SERVER_USER_AGENT"
            ])
        } else if path == "/v3/get_headers" {
            let json: [String: String] = Self.rejectBlob
                ? ["result": "GetHeadersError", "message": "ADI error -45061"]
                : ["result": "Headers", "X-Apple-I-MD": "fresh-otp", "X-Apple-I-MD-M": "machine"]
            data = try! JSONSerialization.data(withJSONObject: json)
        } else if path.hasSuffix("/GsService2") {
            data = try! PropertyListSerialization.data(fromPropertyList: [
                "Response": ["Status": ["hsc": 434, "ec": -1, "X-Apple-I-MD-DATA": Data([1, 2, 3])]]
            ], format: .xml, options: 0)
        } else if path.hasSuffix("/lookup") {
            data = try! PropertyListSerialization.data(fromPropertyList: ["urls": [
                "midStartProvisioning": "https://memfix.invalid/spim",
                "midFinishProvisioning": "https://memfix.invalid/finish"
            ]], format: .xml, options: 0)
        } else {
            // Stop the mocked provisioning flow after inspecting the direct SPIM request.
            status = 418
            data = Data("mock SPIM stop".utf8)
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
}

@Suite("Windows anisette authentication", .serialized)
struct AnisetteAuthTests {
    init() {
        URLProtocol.registerClass(AnisetteAuthURLProtocol.self)
        AnisetteAuthURLProtocol.requests = []
        AnisetteAuthURLProtocol.rejectBlob = false
        AnisetteAuthURLProtocol.emptyIdentity = false
    }

    let server = URL(string: "https://memfix.invalid")!
    let identifier = UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!
    let blob = Data([10, 20, 30])

    var legacyHeaders: AnisetteRequestHeaders {
        AnisetteRequestHeaders().with {
            $0.clientInfo = "<Pixel 8> <Android>"
            $0.userAgent = "old Mac agent"
        }
    }

    @Test func negotiatesIdentityAndResyncsWithExistingBlobWithoutActiveMode() async throws {
        let manager = AnisetteDataManager(baseDirectory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
        let result = try await manager.fetchAnisetteDataWithFailover(
            servers: [server], identifier: identifier, existingAdiBlob: blob, headers: legacyHeaders
        )
        #expect(manager.activeMode == nil)
        #expect(result.data.clientInfo == "WINDOWS_SERVER_IDENTITY")
        #expect(result.data.userAgent == "SERVER_USER_AGENT")
        let fresh = try await manager.resync(sim: "SIM_DATA", currentData: result.data)
        #expect(fresh.oneTimePassword == "fresh-otp")
        let request = try #require(AnisetteAuthURLProtocol.requests.last)
        let json = try #require(JSONSerialization.jsonObject(with: try body(request)) as? [String: String])
        #expect(json["adi_pb"] == blob.base64EncodedString())
        #expect(json["identifier"] == "ABEiM0RVZneImaq7zN3u/w==")
        #expect(json["sim"] == "SIM_DATA")
        #expect(json["device_id"] == identifier.uuidString)
        #expect(json["md_lu"] == result.data.localUserID)
        #expect(json["md_lu"]?.count == 64)
        #expect(request.url?.host == server.host)
    }

    @Test func reprovisionsOn45061AndSendsNegotiatedHeadersToSPIM() async throws {
        AnisetteAuthURLProtocol.rejectBlob = true
        let manager = AnisetteDataManager(baseDirectory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
        do {
            _ = try await manager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, existingAdiBlob: blob, headers: legacyHeaders)
            Issue.record("Mock SPIM stop should fail provisioning")
        } catch {
            #expect(error.localizedDescription.contains("418"))
        }
        let spim = try #require(AnisetteAuthURLProtocol.requests.first(where: { $0.url?.path == "/spim" }))
        #expect(spim.value(forHTTPHeaderField: "X-Mme-Client-Info") == "WINDOWS_SERVER_IDENTITY")
        #expect(spim.value(forHTTPHeaderField: "User-Agent") == "SERVER_USER_AGENT")
        #expect(AnisetteAuthURLProtocol.requests.filter { $0.url?.path == "/v3/get_headers" }.count == 1)
    }

    @Test func grandSlamUsesAnisetteIdentityAndReturns434ForResync() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [AnisetteAuthURLProtocol.self]
        var overrides = SideSignHeaders()
        overrides.grandSlam.userAgent = "stale Xcode user agent"
        let portal = DeveloperPortal(session: URLSession(configuration: config), customHeaders: overrides)
        let data = AnisetteData(machineID: "m", oneTimePassword: "o", localUserID: "l", routingInfo: "0",
                                deviceID: "d", serialNumber: "0", clientInfo: "WINDOWS_SERVER_IDENTITY",
                                userAgent: "SERVER_USER_AGENT", clientTime: "2026-10-15T00:00:00Z", locale: "en_US", timeZone: "UTC")
        let response = try await portal.sendAuthenticationRequest(parameters: [:], anisetteData: data)
        #expect((response["Status"] as? [String: any Sendable])?["hsc"] as? Int == 434)
        let request = try #require(AnisetteAuthURLProtocol.requests.last)
        #expect(request.value(forHTTPHeaderField: "User-Agent") == "SERVER_USER_AGENT")
        #expect(request.value(forHTTPHeaderField: "X-MMe-Client-Info") == "WINDOWS_SERVER_IDENTITY")
    }

    @Test func rejectsEmptyMetadataBeforeContactingApple() async throws {
        AnisetteAuthURLProtocol.emptyIdentity = true
        do {
            _ = try await RemoteAnisetteDataProvider(serverURL: server).fetchClientInfo()
            Issue.record("Empty client identity must be rejected")
        } catch {
            #expect(error is SideSign.AnisetteError)
        }
        #expect(AnisetteAuthURLProtocol.requests.count == 1)
    }

    private func body(_ request: URLRequest) throws -> Data {
        if let data = request.httpBody { return data }
        let stream = try #require(request.httpBodyStream)
        stream.open()
        defer { stream.close() }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count <= 0 { break }
            result.append(buffer, count: count)
        }
        return result
    }
}
