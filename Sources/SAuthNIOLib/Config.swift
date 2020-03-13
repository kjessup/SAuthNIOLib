//
//  Config.swift
//  SAuthNIOLib
//
//  Created by Kyle Jessup on 2020-03-12.
//

import Foundation
import PerfectCrypto
import PerfectLib

public struct Config: Codable {
	public static var globalConfig: Config!
	
	public struct Server: Codable {
		public let port: Int
		public let name: String
		public let privateKeyPath: String?
		public let certificateChainPath: String?
		public let privateKeyName: String
		public let publicKeyName: String
		
		public var serverPrivateKey: PEMKey { try! PEMKey(pemPath: "\(privateKeyName)") }
		public var serverPublicKeyStr: String { try! File("\(publicKeyName)").readString() }
		public var serverPublicKey: PEMKey { try! PEMKey(source: serverPublicKeyStr) }
		public var serverPublicKeyJWK: JWK { try! JWK(key: serverPublicKey) }
		public var serverPublicKeyJWKStr: String { String(data: try! JSONEncoder().encode(serverPublicKeyJWK), encoding: .utf8)! }
	}
	public struct URIs: Codable {
		public let passwordReset: String?
		public let accountValidate: String?
		public let oauthRedirect: String?
		public let profilePicsFSPath: String?
		public let profilePicsWebPath: String?
	}
	public struct SMTP: Codable {
		public let host: String
		public let port: Int
		public let user: String
		public let password: String
		public let fromName: String
		public let fromAddress: String
	}
	// compat
	public struct Notifications: Codable {
		public let keyName: String
		public let keyId: String
		public let teamId: String
		public let topic: String
		public let production: Bool
	}
	public struct Database: Codable {
		public let host: String
		public let port: Int
		public let name: String
		public let user: String
		public let password: String
	}
	public struct Templates: Codable {
		public let passwordResetForm: String
		public let passwordResetOk: String
		public let passwordResetError: String
		public let passwordResetEmail: String?
		public let accountValidationEmail: String?
		public let accountValidationError: String?
		public let accountValidationOk: String?
	}
	public struct Redis: Codable {
		public let host: String
		public let port: Int?
	}
	public struct Enable: Codable {
		public let userSelfRegistration: Bool
		public let adminRoutes: Bool
		public let userProfileUpdate: Bool
		public let promptFirstAccount: Bool
		public let readinessCheck: Bool
		public let onDevicePWReset: Bool
		public let oauthRoutes: Bool
	}
	public struct ClientApp: Codable {
		public let name: String
		public let keyName: String
		public let keyId: String
		public let teamId: String
		public let topic: String
		public let production: Bool
	}
	
	public let server: Server
	public let uris: URIs
	
	public let smtp: SMTP?
	public let notifications: Notifications?
	public var database: Database?
	public let templates: Templates?
	public let redis: Redis?
	public var enable: Enable?
	public var clientApps: [ClientApp]?
	
	public static func get(from f: File) throws -> Config {
		let config = try JSONDecoder().decode(Config.self, from: Data(Array(f.readString().utf8)))
		return config
	}
	public static func get() throws -> Config {
		let config = try Config(from: EnvVarDecoder())
		return config
	}
}
