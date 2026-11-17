import SwiftUI

struct RootView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        NavigationStack {
            if model.glassesId == nil { PickGlassesView() } else { HomeView() }
        }
    }
}

struct PickGlassesView: View {
    @EnvironmentObject var model: AppModel
    @StateObject private var scanner = Scanner()
    var body: some View {
        List {
            Section {
                Text(scanner.status).font(.footnote).foregroundStyle(.secondary)
            }
            Section("Glasses nearby") {
                ForEach(scanner.found) { g in
                    Button { model.choose(g) } label: {
                        HStack {
                            VStack(alignment: .leading) { Text(g.name); Text("\(g.rssi) dBm").font(.caption).foregroundStyle(.secondary) }
                            Spacer()
                            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                        }
                    }
                }
                if scanner.found.isEmpty { ProgressView() }
            }
        }
        .navigationTitle("Pick your glasses")
        .onAppear { scanner.start() }
        .onDisappear { scanner.stop() }
    }
}

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List {
            Section {
                HStack {
                    Image(systemName: "eyeglasses").font(.largeTitle)
                    VStack(alignment: .leading) {
                        Text(model.glassesName.isEmpty ? "Meta glasses" : model.glassesName).font(.headline)
                        Text(statusText).font(.subheadline).foregroundStyle(statusColor)
                    }
                }
                if model.phase == .idle || isFailed {
                    Button("Connect") { model.connect() }
                } else {
                    Button("Disconnect", role: .destructive) { model.disconnect() }
                }
            }
            if !model.hasIdentity {
                Section {
                    Label("This phone is not the owner of these glasses yet. Meta login and setup are not ported, so the link comes up without trust and the glasses will likely close it.", systemImage: "info.circle")
                        .font(.footnote)
                }
            }
            Section("Event log") {
                if model.log.isEmpty { Text("Nothing yet").foregroundStyle(.secondary) }
                ForEach(Array(model.log.enumerated()), id: \.offset) { _, line in
                    Text(line).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }
            Section {
                Button("Pick other glasses", role: .destructive) { model.forget() }
            }
        }
        .navigationTitle("Visor")
        .toolbar { ToolbarItem(placement: .primaryAction) { ShareLink(item: model.log.joined(separator: "\n")) } }
    }

    private var isFailed: Bool { if case .failed = model.phase { return true }; return false }
    private var statusText: String {
        switch model.phase {
        case .idle: return "Not connected"
        case .connecting: return "Connecting…"
        case .handshaking: return "Securing the link…"
        case .up: return "Connected"
        case .failed(let why): return "Failed: \(why)"
        }
    }
    private var statusColor: Color {
        switch model.phase { case .up: return .green; case .failed: return .red; default: return .secondary }
    }
}
