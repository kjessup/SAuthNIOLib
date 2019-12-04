//
//  OAuth.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-02-26.
//

import Foundation
import PerfectNIO
import SAuthCodables

public enum OAuthProvider: String {
	case google = "google"
	case facebook = "facebook"
	case linkedin = "linkedin"
}

public struct OAuthProviderAndToken: Codable {
	let provider: String
	let token: String
}

public struct OAuthHandlers<S: SAuthConfigProvider> {
	let sauthDB: S
	public init(_ s: S) {
		sauthDB = s
	}
	
	public func oauthReturnHandler(request: HTTPRequest) -> HTTPOutput {
		guard let uri = try? sauthDB.getURI(.oauthRedirect) else {
			return ErrorOutput(status: .badRequest, description: "URIs not configured.")
		}
		let provider = request.uriVariables["provider"] ?? ""
		let str = request.searchArgs?.map { "\($0.0.stringByEncodingURL)=\($0.1.stringByEncodingURL)" }.joined(separator: "&") ?? ""
		let url = "\(uri)\(provider)/?\(str)"
		return BytesOutput(head: HTTPHead(status: .temporaryRedirect, headers: HTTPHeaders([("Location", url)])), body: [])
	}
	
	public func oauthLoginHandler(provTok: OAuthProviderAndToken) throws -> TokenAcquiredResponse<S.MetaType> {
		guard let provider = OAuthProvider(rawValue: provTok.provider) else {
			throw ErrorOutput(status: .badRequest, description: "Bad provider.")
		}
		switch provider {
		case .google:
			guard let gInfo = getGooglePlusData(provTok.token),
				let address = gInfo.email else {
				throw ErrorOutput(status: .badRequest, description: "Unable to get Google profile info.")
			}
//			let meta = AccountPublicMeta(fullName: gInfo.displayName)
			let tokenResponse = try SAuth(self.sauthDB).createOrLogIn(provider: provTok.provider,
								accessToken: provTok.token,
								address: address,
								meta: nil as S.MetaType?)
			return tokenResponse
		case .facebook:
			guard let gInfo = getFacebookData(provTok.token) else {
				throw ErrorOutput(status: .badRequest, description: "Unable to get Facebook profile info.")
			}
//			let meta = AccountPublicMeta(fullName: gInfo.name)
			let tokenResponse = try SAuth(self.sauthDB).createOrLogIn(provider: provTok.provider,
																	  accessToken: provTok.token,
																	  address: gInfo.email,
																	  meta: nil as S.MetaType?)
			return tokenResponse
		case .linkedin:
			guard let gInfo = getLinkedInData(provTok.token) else {
				throw ErrorOutput(status: .badRequest, description: "Unable to get LinkedIn profile info.")
			}
//			let meta = AccountPublicMeta(fullName: "\(gInfo.firstName) \(gInfo.lastName)")
			let tokenResponse = try SAuth(self.sauthDB).createOrLogIn(provider: provTok.provider,
																	  accessToken: provTok.token,
																	  address: gInfo.emailAddress,
																	  meta: nil as S.MetaType?)
			return tokenResponse
		}
	}
}





