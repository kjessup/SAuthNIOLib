//
//  SAuthLib.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-02-26.
//

import Foundation
import PerfectNIO
import PerfectCrypto
import PerfectCRUD
import PerfectNotifications
import SAuthCodables

public let authCookieName = "sauth_token" // !FIX!

let passwordResetTokenExpirationIntervalSeconds = 15 * 60

public extension Date {
	var sauthTimeInterval: Int {
		return Int(timeIntervalSince1970)
	}
}

public struct AuthenticatedRequest<Meta: Codable> {
	public let request: HTTPRequest
	public let token: String
	public let account: Account<Meta>
	public let aliasId: String
}

extension AliasBrief {
	init(_ alias: Alias) {
		self.init(address: alias.address,
				  account: alias.account,
				  priority: alias.priority,
				  flags: alias.flags,
				  defaultLocale: alias.defaultLocale)
	}
}

public struct SAuthHandlers<S: SAuthConfigProvider> {
	public let sauthDB: S
	public init(_ s: S) {
		sauthDB = s
	}
	public func register(request: AuthAPI.RegisterRequest<S.MetaType>) throws -> AliasBrief {
		let (account, alias) = try SAuth(sauthDB).createAccount(address: request.email,
																password: request.password,
																meta: request.meta)
		let token = try addAliasValidationToken(address: alias.address, db: try sauthDB.getDB())
		let aliasBrief = AliasBrief(alias)
		do {
			try sauthDB.sendEmailValidation(authToken: token, account: account, alias: aliasBrief)
		} catch {
			try SAuth(sauthDB).badAudit(db: try sauthDB.getDB(), alias: alias.address, action: "email", error: "\(error)")
		}
		return aliasBrief
	}
	public func login(request: AuthAPI.LoginRequest) throws -> TokenAcquiredResponse<S.MetaType> {
		let tokenResponse: TokenAcquiredResponse<S.MetaType> = try SAuth(sauthDB).logIn(
			address: request.email,
			password: request.password)
		let db = try sauthDB.getDB()
		let table = db.table(PasswordResetToken.self)
		try table.where(\PasswordResetToken.aliasId == request.email.lowercased()).delete()
		return tokenResponse
	}
	
	private func getToken(authorization request: HTTPRequest) -> String? {
		guard let bearer = request.headers["authorization"].first, !bearer.isEmpty else {
			return nil
		}
		let prefix = "Bearer "
		let token: String
		if bearer.hasPrefix(prefix) {
			token = String(bearer[bearer.index(bearer.startIndex, offsetBy: prefix.count)...])
		} else {
			token = bearer
		}
		return token
	}
	
	private func getToken(cookie request: HTTPRequest) -> String? {
		guard let token = request.cookies[authCookieName], !token.isEmpty else {
			return nil
		}
		return token
	}
	
	public func authenticated(request: HTTPRequest) throws -> AuthenticatedRequest<S.MetaType> {
		guard let token = getToken(authorization: request) ?? getToken(cookie: request) else {
			throw ErrorOutput(status: .unauthorized, description: "No authorization provided.")
		}
		do {
			if let jwtVer = JWTVerifier(token) {
				try jwtVer.verify(algo: .rs256, key: sauthDB.getServerPublicKey())
				let payload = jwtVer.payload
				let table = try sauthDB.getDB().table(Account<S.MetaType>.self)
				if let accountIdStr = payload["accountId"] as? String,
					let accountId = UUID(uuidString: accountIdStr),
					let alias = payload["sub"]as? String,
					let account = try table.where(\Account<S.MetaType>.id == accountId).first() {
					return AuthenticatedRequest(request: request,
												token: token,
												account: account,
												aliasId: alias)
				}
			}
		} catch {}
		throw ErrorOutput(status: .unauthorized, description: "Invalid authorization header provided.")
	}
	public func getMe(request: AuthenticatedRequest<S.MetaType>) throws -> Account<S.MetaType> {
		let account: Account<S.MetaType> = try SAuth(sauthDB).getAccount(token: request.token)
		return account
	}
	public func getMeMeta(request: AuthenticatedRequest<S.MetaType>) throws -> S.MetaType {
		guard let meta: S.MetaType = try SAuth(sauthDB).getMeta(token: request.token) else {
			throw ErrorOutput(status: .unauthorized, description: "Unable to fetch meta data.")
		}
		return meta
	}
	public func setMeMeta(request: AuthenticatedRequest<S.MetaType>, meta: S.MetaType) throws -> EmptyReply {
		try SAuth(sauthDB).setMeta(token: request.token, meta: meta)
		return EmptyReply()
	}
	public func addMobileDevice(request: AuthenticatedRequest<S.MetaType>, addReq: AuthAPI.AddMobileDeviceRequest) throws -> EmptyReply {
		let deviceId = addReq.deviceId
		let db = try sauthDB.getDB()
		let add = MobileDeviceId(deviceId: deviceId,
								 deviceType: addReq.deviceType,
								 aliasId: request.aliasId,
								 createdAt: Date().sauthTimeInterval)
		do {
			_ = try db.table(MobileDeviceId.self).insert(add)
		} catch {
			// unique constraint conflict is expected here
		}
		return EmptyReply()
	}
	private func addAliasValidationToken(address loweredAddress: String, db: Database<S.DBConfig>) throws -> String {
		let authId = UUID().uuidString
		let table = db.table(AccountValidationToken.self)
		try table.where(\AccountValidationToken.aliasId == loweredAddress).delete()
		let token = AccountValidationToken(aliasId: loweredAddress, authId: authId, createdAt: Date().sauthTimeInterval)
		try table.insert(token)
		return authId
	}
}

extension SAuthHandlers {
	public func pwResetWeb(request: HTTPRequest) throws -> HTTPOutput {
		guard let token = request.uriVariables["token"], !token.isEmpty else {
			return ErrorOutput(status: .notFound)
		}
		guard let tempForm = try? sauthDB.getTemplatePath(.passwordResetForm),
			let tempErr = try? sauthDB.getTemplatePath(.passwordResetError) else {
				return ErrorOutput(status: .badRequest, description: "Templates not configured.")
		}
		do {
			let db = try sauthDB.getDB()
			let table = db.table(PasswordResetToken.self)
			let whereToken = table.where(\PasswordResetToken.authId == token)
			let newToken = try db.transaction {
				() -> PasswordResetToken? in
				guard let resetToken = try whereToken.first() else {
					throw ErrorOutput(status: .notFound, description: "Token not found.")
				}
				let addr = resetToken.aliasId
				guard resetToken.expiration > Date().sauthTimeInterval else {
					try table.where(\PasswordResetToken.aliasId == addr).delete()
					return nil
				}
				return resetToken
			}
			guard let newResetToken = newToken else {
				throw ErrorOutput(status: .notFound, description: "Token not found.")
			}
			let dict: [String:Any] = ["token":newResetToken.authId, "address":newResetToken.aliasId]
			return try MustacheOutput(templatePath: tempForm, inputs: dict, contentType: "text/html")
		} catch {
			return try MustacheOutput(templatePath: tempErr, inputs: ["error":error], contentType: "text/html")
		}
	}
	public func pwResetWebComplete(resetRequest: AuthAPI.PasswordResetCompleteRequest) throws -> HTTPOutput {
		guard let tempOk = try? sauthDB.getTemplatePath(.passwordResetOk),
			let tempErr = try? sauthDB.getTemplatePath(.passwordResetError) else {
				return ErrorOutput(status: .internalServerError, description: "Templates not configured.")
		}
		do {
			_ = try completePasswordReset(resetRequest: resetRequest)
			return try MustacheOutput(templatePath: tempOk, inputs: [:], contentType: "text/html")
		} catch {
			return try MustacheOutput(templatePath: tempErr, inputs: ["error":error], contentType: "text/html")
		}
	}
}

extension SAuthHandlers {
	public func accountValidateWeb(request: HTTPRequest) throws -> HTTPOutput {
		guard let token = request.uriVariables["token"], !token.isEmpty else {
			return ErrorOutput(status: .notFound)
		}
		guard let tempOk = try? sauthDB.getTemplatePath(.accountValidationOk),
			let tempErr = try? sauthDB.getTemplatePath(.accountValidationError) else {
				return ErrorOutput(status: .badRequest, description: "Templates not configured.")
		}
		do {
			let db = try sauthDB.getDB()
			let validationTable = db.table(AccountValidationToken.self)
			let aliasTable = db.table(AliasBrief.self)
			let clause = validationTable.where(\AccountValidationToken.authId == token)
			if let result = try db.transaction({
				() -> HTTPOutput? in
				guard let row = try clause.first() else {
					return ErrorOutput(status: .notFound)
				}
				try clause.delete()
				guard let alias = try aliasTable.where(\AliasBrief.address == row.aliasId).first() else {
					return ErrorOutput(status: .notFound)
				}
				if alias.provisional {
					let newAlias = AliasBrief(address: alias.address,
											  account: alias.account,
											  priority: alias.priority,
											  flags: alias.flags & ~AliasFlags.provisional.rawValue,
											  defaultLocale: alias.defaultLocale)
					try aliasTable.where(\AliasBrief.address == row.aliasId).update(newAlias, setKeys: \.flags)
				}
				return nil
			}) {
				return result
			}
			return try MustacheOutput(templatePath: tempOk, inputs: [:], contentType: "text/html")
		} catch {
			return try MustacheOutput(templatePath: tempErr, inputs: ["error":error], contentType: "text/html")
		}
	}
}

extension SAuthHandlers {
	private func addPasswordResetToken(address loweredAddress: String, db: Database<S.DBConfig>) throws -> String {
		let authId = UUID().uuidString
		let table = db.table(PasswordResetToken.self)
		try table.where(\PasswordResetToken.aliasId == loweredAddress).delete()
		let exp = Date().sauthTimeInterval + passwordResetTokenExpirationIntervalSeconds
		let token = PasswordResetToken(aliasId: loweredAddress, authId: authId, expiration: exp)
		try table.insert(token)
		return authId
	}
	
	public func initiatePasswordReset(resetRequest: AuthAPI.PasswordResetRequest) throws -> EmptyReply {
		let loweredAddress = resetRequest.address.lowercased()
		let db = try sauthDB.getDB()
		guard let alias = try db.table(AliasBrief.self).where(\AliasBrief.address == loweredAddress).first() else {
			throw ErrorOutput(status: .badRequest, description: "Bad account alias.")
		}
		let authId = try db.transaction {
			return try addPasswordResetToken(address: loweredAddress, db: db)
		}
		let deviceTable = db.table(MobileDeviceId.self)
		if let deviceId = resetRequest.deviceId,
			try deviceTable
			.where(\MobileDeviceId.aliasId == loweredAddress &&
				\MobileDeviceId.deviceType == "ios" &&
				\MobileDeviceId.deviceId == deviceId).count() == 1 {
			let n = NotificationPusher(apnsTopic: try sauthDB.getPushConfigurationTopic(forType: "ios"))
			n.pushAPNS(
				configurationName: try sauthDB.getPushConfigurationName(forType: "ios"),
				deviceTokens: [deviceId],
				notificationItems: [.customPayload("auth", authId), .alertBody("password reset")]) {
					responses in
					guard let f = responses.first else {
						return
					}
					if case .ok = f.status {
						// !FIX! wait N minutes and if the token is still there send an email?
						return
					} else {
						_ = try? self.sendEmailPasswordReset(address: loweredAddress, authId: authId, alias: alias, db: db)
					}
			}
			return EmptyReply()
		}
		return try sendEmailPasswordReset(address: loweredAddress, authId: authId, alias: alias, db: db)
	}
	
	private func sendEmailPasswordReset(address loweredAddress: String,
										authId: String,
										alias: AliasBrief,
										db: Database<S.DBConfig>) throws -> EmptyReply {
		guard let account = try db.table(Account<S.MetaType>.self).where(\Account<S.MetaType>.id == alias.account).first() else {
			throw ErrorOutput(status: .badRequest, description: "Bad account.")
		}
		try sauthDB.sendEmailPasswordReset(authToken: authId,
										   account: account,
										   alias: alias)
		return EmptyReply()
	}
	
	public func completePasswordReset(resetRequest: AuthAPI.PasswordResetCompleteRequest) throws -> TokenAcquiredResponse<S.MetaType> {
		let loweredAddress = resetRequest.address.lowercased()
		do {
			let db = try sauthDB.getDB()
			try db.transaction {
				guard try db.table(Alias.self).where(\Alias.address == loweredAddress).count() == 1 else {
					throw ErrorOutput(status: .badRequest, description: "Bad account alias.")
				}
				let table = db.table(PasswordResetToken.self)
				guard try table.where(\PasswordResetToken.aliasId == loweredAddress &&
					\PasswordResetToken.authId == resetRequest.authToken &&
					\PasswordResetToken.expiration > Date().sauthTimeInterval).count() == 1 else {
						throw ErrorOutput(status: .badRequest, description: "Bad password reset token.")
				}
				try table.where(\PasswordResetToken.aliasId == loweredAddress).delete()
			}
		}
		return try SAuth(sauthDB).changePasswordUnchecked(address: loweredAddress, password: resetRequest.password)
	}
}
