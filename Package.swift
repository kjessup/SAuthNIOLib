// swift-tools-version:5.1
import PackageDescription

let package = Package(
	name: "SAuthNIOLib",
	platforms: [
		.macOS(.v10_15)
	],
	products: [
		.library(name: "SAuthNIOLib", targets: ["SAuthNIOLib"])
	],
	dependencies: [
		.package(url: "https://github.com/kjessup/SAuthCodables.git", .branch("master")),
		.package(url: "https://github.com/PerfectlySoft/Perfect-CRUD.git", from: "2.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-NIO.git", .branch("master")),
		.package(url: "https://github.com/PerfectlySoft/Perfect-Notifications.git", from: "4.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", from: "4.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", from: "4.0.0"),
	],
	targets: [
		.target(name: "SAuthNIOLib", dependencies: ["SAuthCodables",
												 "PerfectSMTP",
												 "PerfectNIO",
												 "PerfectCURL",
												 "PerfectCRUD",
												 "PerfectNotifications"])
	]
)
