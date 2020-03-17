//
//  EnvVarDecoder.swift
//  SAuthNIOLib
//
//  Created by Kyle Jessup on 2020-03-11.
//

import Foundation

public struct EnvDecoderError: Error, CustomStringConvertible {
	public let description: String
	init(description: String) {
		self.description = description
	}
	init(missingKey key: String) {
		self.description = "Missing required config key \(key)"
	}
}

struct EnvKey: CodingKey{
	let stringValue: String
	let intValue: Int?
	init?(stringValue: String) {
		self.stringValue = stringValue
		self.intValue = nil
	}
	init?(intValue: Int) {
		self.stringValue = "\(intValue)"
		self.intValue = intValue
	}
}

public class EnvVarDecoder: Decoder {
	public var codingPath: [CodingKey]
	public var userInfo: [CodingUserInfoKey : Any]
	
	static let env = ProcessInfo.processInfo.environment
	static let envKeys = Set(env.keys)
	
	public init(codingPath: [CodingKey] = [], userInfo: [CodingUserInfoKey : Any] = [:]) {
		self.codingPath = codingPath
		self.userInfo = userInfo
	}
	
	public func decode<C: Decodable>(_ type: C.Type) throws -> C {
		return try C.init(from: self)
	}
	
	public func container<KKey>(keyedBy type: KKey.Type) throws -> KeyedDecodingContainer<KKey> where KKey : CodingKey {
		return KeyedDecodingContainer(ObjectReader(codingPath: codingPath))
	}
	
	public func unkeyedContainer() throws -> UnkeyedDecodingContainer {
		return ObjectArrayReader(codingPath: codingPath)
	}
	
	public func singleValueContainer() throws -> SingleValueDecodingContainer {
		return ObjectPropertyReader(codingPath: codingPath)
	}
}

fileprivate func joinKeys(codingPath: [CodingKey]) -> String {
	return codingPath.map { $0.stringValue }.joined(separator: "_")
}

fileprivate func value(forKey: String) -> String? {
	let value = EnvVarDecoder.env[forKey]
//	print("k:v \(forKey):\(value)")
	return value
}

fileprivate func tvalue(forKey: String) throws -> String {
	guard let value = value(forKey: forKey) else {
		throw EnvDecoderError(missingKey: forKey)
	}
	return value
}

class ObjectReader<K : CodingKey>: KeyedDecodingContainerProtocol {
	typealias Key = K
	let allKeys: [K] = []
	let codingPath: [CodingKey]
	init(codingPath: [CodingKey]) {
		self.codingPath = codingPath
//		print("codingPath \(codingPath.map { $0.stringValue })")
	}
	
	func contains(_ key: K) -> Bool {
		var path = joinKeys(codingPath: codingPath + [key])
		if nil != value(forKey: path) {
			return true
		}
		path += "_"
		return nil != EnvVarDecoder.env.keys.first(where: { $0.hasPrefix(path) })
	}
	
	func decodeNil(forKey key: K) throws -> Bool {
		return !contains(key)
	}
	
	func decode(_ type: Bool.Type, forKey key: K) throws -> Bool {
		return Bool(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? false
	}
	
	func decode(_ type: String.Type, forKey key: K) throws -> String {
		return try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) 
	}
	
	func decode(_ type: Double.Type, forKey key: K) throws -> Double {
		return Double(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: Float.Type, forKey key: K) throws -> Float {
		return Float(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: Int.Type, forKey key: K) throws -> Int {
		return Int(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: Int8.Type, forKey key: K) throws -> Int8 {
		return Int8(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: Int16.Type, forKey key: K) throws -> Int16 {
		return Int16(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: Int32.Type, forKey key: K) throws -> Int32 {
		return Int32(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: Int64.Type, forKey key: K) throws -> Int64 {
		return Int64(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: UInt.Type, forKey key: K) throws -> UInt {
		return UInt(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: UInt8.Type, forKey key: K) throws -> UInt8 {
		return UInt8(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: UInt16.Type, forKey key: K) throws -> UInt16 {
		return UInt16(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: UInt32.Type, forKey key: K) throws -> UInt32 {
		return UInt32(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode(_ type: UInt64.Type, forKey key: K) throws -> UInt64 {
		return UInt64(try tvalue(forKey: joinKeys(codingPath: codingPath + [key])) ) ?? 0
	}
	
	func decode<T>(_ type: T.Type, forKey key: K) throws -> T where T : Decodable {
		return try T.init(from: EnvVarDecoder(codingPath: codingPath + [key], userInfo: [:]))
	}
	
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: K) throws -> KeyedDecodingContainer<NestedKey> where NestedKey : CodingKey {
		let newks: [NestedKey] = (codingPath + [key]).compactMap { NestedKey(stringValue: $0.stringValue) }
		return KeyedDecodingContainer(ObjectReader<NestedKey>(codingPath: newks))
	}
	
	func nestedUnkeyedContainer(forKey key: K) throws -> UnkeyedDecodingContainer {
		return ObjectArrayReader(codingPath: codingPath + [key])
	}
	
	func superDecoder() throws -> Decoder {
		fatalError()
	}
	
	func superDecoder(forKey key: K) throws -> Decoder {
		fatalError()
	}
}

class ObjectArrayReader: UnkeyedDecodingContainer {
	var count: Int? = 0
	var isAtEnd: Bool { count! <= currentIndex }
	var currentIndex: Int = 0
	let codingPath: [CodingKey]
	let ids: [(String, [String])]
	// a_b_0_foo=1
	// a_b_0_bar=2
	// a_b_1_foo=3
	// a_b_1_bar=4
	//
	// a_b_NAME2_foo=3
	// a_b_NAME2_bar=4
	init(codingPath: [CodingKey]) {
		self.codingPath = codingPath
		let pathStr = joinKeys(codingPath: codingPath) + "_"
		let validKeys = EnvVarDecoder.envKeys.filter { $0.hasPrefix(pathStr) }.sorted()
		var dict: [String:[String]] = [:]
		for key in validKeys {
			let splt = key.split(separator: "_").map(String.init)
			guard splt.count > codingPath.count else {
				continue
			}
			let n = splt[codingPath.count]
			let exists = dict[n] ?? []
			dict[n] = exists + [key]
		}
		ids = dict.map { $0 }.sorted(by: { $0.0 < $1.0 })
		count = ids.count
//		print("codingPath \(codingPath.map { $0.stringValue })")
//		print("ids \(ids)")
	}
	func grp() -> (String, [String]) {
		let grp = ids[currentIndex]
		currentIndex += 1
		return grp
	}
	
	func sgrpval() throws -> String {
		return try tvalue(forKey: grp().1[0])
	}
	
	func decodeNil() throws -> Bool {
		false
	}
	
	func decode(_ type: Bool.Type) throws -> Bool {
		return Bool(try sgrpval() ) ?? false
	}
	
	func decode(_ type: String.Type) throws -> String {
		return String(try sgrpval() )
	}
	
	func decode(_ type: Double.Type) throws -> Double {
		return Double(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: Float.Type) throws -> Float {
		return Float(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: Int.Type) throws -> Int {
		return Int(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: Int8.Type) throws -> Int8 {
		return Int8(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: Int16.Type) throws -> Int16 {
		return Int16(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: Int32.Type) throws -> Int32 {
		return Int32(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: Int64.Type) throws -> Int64 {
		return Int64(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: UInt.Type) throws -> UInt {
		return UInt(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: UInt8.Type) throws -> UInt8 {
		return UInt8(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: UInt16.Type) throws -> UInt16 {
		return UInt16(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: UInt32.Type) throws -> UInt32 {
		return UInt32(try sgrpval() ) ?? 0
	}
	
	func decode(_ type: UInt64.Type) throws -> UInt64 {
		return UInt64(try sgrpval() ) ?? 0
	}
	
	func decode<T>(_ type: T.Type) throws -> T where T : Decodable {
		let g = grp()
		return try T.init(from: EnvVarDecoder(codingPath: codingPath + [EnvKey(stringValue: g.0)!], userInfo: [:]))
	}
	
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey : CodingKey {
		let grp = ids[currentIndex] // ?? increment ??
		let newks: [NestedKey] = (codingPath + [EnvKey(stringValue: grp.0)!]).compactMap { NestedKey(stringValue: $0.stringValue) }
		return KeyedDecodingContainer(ObjectReader<NestedKey>(codingPath: newks))
	}
	
	func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
		let grp = ids[currentIndex] // ?? increment ??
		return ObjectArrayReader(codingPath: codingPath + [EnvKey(stringValue: grp.0)!])
	}
	
	func superDecoder() throws -> Decoder {
		fatalError()
	}
}

class ObjectPropertyReader: SingleValueDecodingContainer {
	
	let codingPath: [CodingKey]
	init(codingPath: [CodingKey]) {
		self.codingPath = codingPath
//		print("codingPath \(codingPath.map { $0.stringValue })")
	}
	
	var env: String? { EnvVarDecoder.env[joinKeys(codingPath: codingPath)] }
	
	func decodeNil() -> Bool {
		return nil == env
	}
	
	func decode(_ type: Bool.Type) throws -> Bool {
		return Bool(env ?? "false") ?? false
	}
	
	func decode(_ type: String.Type) throws -> String {
		return env ?? ""
	}
	
	func decode(_ type: Double.Type) throws -> Double {
		return Double(env ?? "0") ?? 0
	}
	
	func decode(_ type: Float.Type) throws -> Float {
		return Float(env ?? "0") ?? 0
	}
	
	func decode(_ type: Int.Type) throws -> Int {
		return Int(env ?? "0") ?? 0
	}
	
	func decode(_ type: Int8.Type) throws -> Int8 {
		return Int8(env ?? "0") ?? 0
	}
	
	func decode(_ type: Int16.Type) throws -> Int16 {
		return Int16(env ?? "0") ?? 0
	}
	
	func decode(_ type: Int32.Type) throws -> Int32 {
		return Int32(env ?? "0") ?? 0
	}
	
	func decode(_ type: Int64.Type) throws -> Int64 {
		return Int64(env ?? "0") ?? 0
	}
	
	func decode(_ type: UInt.Type) throws -> UInt {
		return UInt(env ?? "0") ?? 0
	}
	
	func decode(_ type: UInt8.Type) throws -> UInt8 {
		return UInt8(env ?? "0") ?? 0
	}
	
	func decode(_ type: UInt16.Type) throws -> UInt16 {
		return UInt16(env ?? "0") ?? 0
	}
	
	func decode(_ type: UInt32.Type) throws -> UInt32 {
		return UInt32(env ?? "0") ?? 0
	}
	
	func decode(_ type: UInt64.Type) throws -> UInt64 {
		return UInt64(env ?? "0") ?? 0
	}
	
	func decode<T>(_ type: T.Type) throws -> T where T : Decodable {
		return try T.init(from: EnvVarDecoder(codingPath: codingPath, userInfo: [:]))
	}
}
