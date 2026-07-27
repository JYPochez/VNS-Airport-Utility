import Foundation

struct FirmwareDownloadService: Sendable {
  var root: URL
  var download:
    @Sendable (URL, @escaping @Sendable (Int64, Int64?) async -> Void) async throws
      -> URL

  init(
    root: URL = Self.defaultRoot(),
    download:
      @escaping @Sendable (
        URL, @escaping @Sendable (Int64, Int64?) async -> Void
      ) async throws -> URL = Self.defaultDownload
  ) {
    self.root = root
    self.download = download
  }

  func downloadImage(
    _ image: FirmwareImage,
    progress: @escaping @Sendable (Int64, Int64?) async -> Void = { _, _ in }
  ) async throws -> URL {
    let localURL = localURL(for: image)
    let fileManager = FileManager.default
    if fileManager.fileExists(atPath: localURL.path),
      let size = try? localURL.resourceValues(forKeys: [.fileSizeKey]).fileSize,
      size > 0
    {
      await progress(Int64(size), Int64(size))
      return localURL
    }

    try fileManager.createDirectory(
      at: localURL.deletingLastPathComponent(), withIntermediateDirectories: true)
    let temporaryURL = try await download(image.location, progress)
    if fileManager.fileExists(atPath: localURL.path) {
      try fileManager.removeItem(at: localURL)
    }
    try fileManager.moveItem(at: temporaryURL, to: localURL)
    return localURL
  }

  func localURL(for image: FirmwareImage) -> URL {
    let preferredURL = firmwareURL(for: image, applicationDirectory: "AirPort Utility")
    if FileManager.default.fileExists(atPath: preferredURL.path) {
      return preferredURL
    }
    let legacyURL = firmwareURL(for: image, applicationDirectory: "NewAirPortUtility")
    return FileManager.default.fileExists(atPath: legacyURL.path) ? legacyURL : preferredURL
  }

  private func firmwareURL(for image: FirmwareImage, applicationDirectory: String) -> URL {
    root
      .appendingPathComponent(applicationDirectory, isDirectory: true)
      .appendingPathComponent("Firmware", isDirectory: true)
      .appendingPathComponent(image.productID, isDirectory: true)
      .appendingPathComponent(image.sourceVersion, isDirectory: true)
      .appendingPathComponent("\(image.version).basebinary")
  }

  private static func defaultRoot() -> URL {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
      ?? FileManager.default.temporaryDirectory
  }

  private static func defaultDownload(
    _ url: URL,
    progress: @escaping @Sendable (Int64, Int64?) async -> Void
  ) async throws -> URL {
    let delegate = FirmwareDownloadProgressDelegate(progress: progress)
    let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
    defer {
      session.finishTasksAndInvalidate()
    }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        delegate.start(url: url, session: session, continuation: continuation)
      }
    } onCancel: {
      delegate.cancel()
    }
  }
}

private final class FirmwareDownloadProgressDelegate: NSObject, URLSessionDownloadDelegate,
  @unchecked Sendable
{
  private let progress: @Sendable (Int64, Int64?) async -> Void
  private let lock = NSLock()
  private var continuation: CheckedContinuation<URL, Error>?
  private var task: URLSessionDownloadTask?
  private var didResume = false

  init(progress: @escaping @Sendable (Int64, Int64?) async -> Void) {
    self.progress = progress
  }

  func start(
    url: URL,
    session: URLSession,
    continuation: CheckedContinuation<URL, Error>
  ) {
    lock.lock()
    self.continuation = continuation
    let task = session.downloadTask(with: url)
    self.task = task
    lock.unlock()
    task.resume()
  }

  func cancel() {
    lock.lock()
    let task = task
    lock.unlock()
    task?.cancel()
  }

  func urlSession(
    _ session: URLSession,
    downloadTask: URLSessionDownloadTask,
    didWriteData bytesWritten: Int64,
    totalBytesWritten: Int64,
    totalBytesExpectedToWrite: Int64
  ) {
    let expected = totalBytesExpectedToWrite > 0 ? totalBytesExpectedToWrite : nil
    let progress = progress
    Task {
      await progress(totalBytesWritten, expected)
    }
  }

  func urlSession(
    _ session: URLSession,
    downloadTask: URLSessionDownloadTask,
    didFinishDownloadingTo location: URL
  ) {
    let temporaryURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("airport-firmware-\(UUID().uuidString)")
      .appendingPathExtension(location.pathExtension.isEmpty ? "download" : location.pathExtension)
    do {
      try FileManager.default.moveItem(at: location, to: temporaryURL)
      finish(.success(temporaryURL))
    } catch {
      finish(.failure(error))
    }
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didCompleteWithError error: Error?
  ) {
    if let error {
      finish(.failure(error))
    }
  }

  private func finish(_ result: Result<URL, Error>) {
    lock.lock()
    guard !didResume else {
      lock.unlock()
      return
    }
    didResume = true
    let continuation = continuation
    self.continuation = nil
    lock.unlock()

    switch result {
    case .success(let url):
      continuation?.resume(returning: url)
    case .failure(let error):
      continuation?.resume(throwing: error)
    }
  }
}
