<div align="center"><img src="images/yamagoya_logo.png" width="600"></div> 

## コンセプト

**YAMAGoya** (Yet Another Memory Analyzer for malware detection and Guarding Operations with YARA and Sigma) は、[Event Tracing for Windows (ETW)](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) を活用してリアルタイムシステムイベントを捕捉するC#アプリケーションです。YAML形式で記述された検知ルール（カスタムルール用）を適用し、標準化された脅威検知のための**Sigma**ルールも解析できます。さらに、**YARA**を使用したメモリ内スキャンをサポートし、ファイルレスまたはステルスマルウェアの検知を行います。

このツールは**ユーザーランド**で動作し、カーネルモードの依存関係を回避し、コミュニティベースのシグネチャとの統合を簡素化します。

## 目次
- [機能](#機能)
- [バイナリ版のダウンロード](#バイナリ版のダウンロード)
- [ビルドとインストール](#ビルドとインストール)
  - [前提条件](#前提条件)
  - [コマンドラインビルド](#コマンドラインビルド)
- [使用方法](#使用方法)
  - [コマンドライン](#コマンドライン)
  - [GUI使用法](#gui使用法)
- [コマンドラインの例](#コマンドラインの例)
  - [ETWセッションの開始](#etwセッションの開始)
  - [ETWセッションの停止](#etwセッションの停止)
  - [検知ルールの適用（YAML）](#検知ルールの適用yaml)
  - [検知ルールの適用（Sigma）](#検知ルールの適用sigma)
  - [メモリスキャンの有効化](#メモリスキャンの有効化)
  - [特定イベントタイプの監視](#特定イベントタイプの監視)
  - [ログ設定](#ログ設定)
  - [高度な設定](#高度な設定)
  - [オールインワンの例](#オールインワンの例)
- [YAMLルールファイルの作成](#yamlルールファイルの作成)
- [Sigmaサポート](#sigmaサポート)
  - [サポートされるSigmaカテゴリ](#サポートされるsigmaカテゴリ)
  - [SigmaからETWへのマッピング](#sigmaからetwへのマッピング)
- [設定とログ](#設定とログ)
- [既知の制限事項・注意点](#既知の制限事項注意点)
- [ライセンス](#ライセンス)
- [FAQ（よくある質問）](#faqよくある質問)

---

## 機能

- **ユーザーランドで動作**  
  カーネルドライバーのインストールは不要で、OSリスクを最小限に抑えることができます。

- **リアルタイム監視**  
  ETWを利用して、ファイルI/O、プロセス作成/終了、レジストリイベント、DNSクエリ、ネットワークトラフィック、PowerShellスクリプトなどを監視します。

- **マルチフォーマット検知ルール**  
  - **YAML**: 正規表現やその他のマッチングロジックを使用して複数のイベントを相関分析できます。  
  - **Sigma**: コミュニティ主導の脅威検知のためのSigmaルールを使用できます。

- **YARAによるメモリスキャン**  
  YARAルールを使用してメモリをスキャンし、ファイルレスまたはステルスマルウェアを検知します。

- **GUI / CLI インターフェース**  
  コマンドラインまたはGUIで実行できます。

---

## バイナリ版のダウンロード

[Release](https://github.com/JPCERTCC/YAMAGoya/releases)からコンパイル済みバージョンをダウンロード可能です。

---

## ビルドとインストール

### 前提条件

- **.NET 6.0以降**  
  適切な.NET SDKまたはランタイムをインストールしてください。
- **NuGet パッケージ**  
  - [Microsoft.Diagnostics.Tracing.TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/)  
  - [YamlDotNet](https://www.nuget.org/packages/YamlDotNet/)  
  - [System.Diagnostics.EventLog](https://www.nuget.org/packages/System.Diagnostics.EventLog/)  
  - [MaterialDesignColors](https://www.nuget.org/packages/MaterialDesignColors/)  
  - [MaterialDesignThemes](https://www.nuget.org/packages/MaterialDesignThemes/)
  - [Antlr4.Runtime.Standard](https://www.nuget.org/packages/Antlr4.Runtime.Standard/)
  - [DynamicExpresso.Core](https://www.nuget.org/packages/DynamicExpresso.Core/)

### コマンドラインビルド

0. NuGetパッケージのインストール:
   ```bash
   dotnet add package Microsoft.Diagnostics.Tracing.TraceEvent
   dotnet add package YamlDotNet
   dotnet add package System.Diagnostics.EventLog
   dotnet add package MaterialDesignThemes
   dotnet add package MaterialDesignColors
   dotnet add package Antlr4.Runtime.Standard
   dotnet add package DynamicExpresso.Core
   ```

1. **リポジトリのクローン**:
   ```bash
   git clone https://github.com/JPCERTCC/YAMAGoya.git
   cd YAMAGoya
   ```
2. **ビルド**:
   ```bash
   dotnet build
   ```
3. （オプション）**自己完結型アプリケーションのパブリッシュ**:
   ```bash
   dotnet publish -c Release -r win-x64 -p:PublishTrimmed=false -o out
   ```

---

## 使用方法

### コマンドライン

#### 基本的な使用法

```bash
YAMAGoya.exe [options]
```

**ステップ1: 環境の準備**
1. 管理者権限があることを確認してください（ETWセッション管理に必要）
2. 検知ルールを準備します：
   - YAMLルールの場合：フォルダに`.yaml`または`.yml`ファイルを作成
   - Sigmaルールの場合：フォルダに`.yml`Sigmaルールファイルを配置  
   - YARAルールの場合：フォルダに`.yar`または`.yara`ファイルを作成

**ステップ2: セッション開始と検知（以下のいずれかの方法を選択）**
```bash
# 方法A: 包括的な監視でSigmaルールを使用
YAMAGoya.exe --session --sigma "C:\Rules\Sigma" --all

# 方法B: YARAメモリスキャン
YAMAGoya.exe --session --yara "C:\Rules\YARA" --all
```

**ステップ3: 高度なオプションの設定（オプション）**
```bash
# 自動プロセス終了と詳細ログを有効化
YAMAGoya.exe --session --detect "C:\Rules" --all --kill --verbose

# カスタムログ設定
YAMAGoya.exe --session --detect "C:\Rules" --all --log_path "D:\SecurityLogs" --no_event_log

# ルールチェック間隔を30秒に設定
YAMAGoya.exe --session --detect "C:\Rules" --all --check_interval 30
```

**ステップ4: 監視の停止**
```bash
# ETWセッションを停止
YAMAGoya.exe --stop
```

#### コマンドラインオプション一覧

| オプション                       | 説明                                                               |
|---------------------------------|-------------------------------------------------------------------|
| `--help, -h`                    | ヘルプメッセージを表示して終了                                      |
| `--session, -s`                 | `"YAMAGoya"`という名前のETWセッションを開始（既存セッションがあれば先に停止） |
| `--stop, -x`                    | アクティブな`"YAMAGoya"`ETWセッションを停止                         |
| `--detect, -d <folder>`         | `<folder>`から検知ルール（YAML）を読み込み、検知を開始              |
| `--sigma, -si <folder>`         | YAMLルールの代わりに`<folder>`からSigmaルールを読み込み・適用         |
| `--yara, -y <folder>`           | メモリスキャン用に`<folder>`からYARAルールを読み込み・適用           |
| `--all, -a`                     | すべてのイベントカテゴリの監視を有効化                              |
| `--file, -f`                    | ファイル**作成**イベントを監視                                      |
| `--delfile, -df`                | ファイル**削除**イベントを監視                                      |
| `--process, -p`                 | プロセス作成・終了イベントを監視                                    |
| `--load, -l`                    | DLL読み込みイベントを監視                                          |
| `--registry, -r`                | レジストリキー/値の作成・変更イベントを監視                          |
| `--open, -o`                    | プロセスオープンイベントを監視                                      |
| `--dns, -n`                     | DNSクエリ・レスポンスを監視                                         |
| `--ipv4, -i4`                   | IPv4ネットワークトラフィックイベントを監視                           |
| `--ipv6, -i6`                   | IPv6ネットワークトラフィックイベントを監視                           |
| `--powershell, -ps1`            | PowerShellスクリプトブロック実行を監視                              |
| `--shell, -sh`                  | シェルイベント（RunKey、ショートカットなど）を監視                   |
| `--wmi, -w`                     | WMIコマンド実行イベントを監視                                       |
| `--kill, -k`                    | 検知された悪意のあるプロセスを自動的に終了                          |
| `--session_name <name>`         | ETWセッションのカスタム名を設定                                     |
| `--no_text_log`                 | テキストファイルへのログ出力を無効化                                |
| `--no_event_log`                | Windowsイベントログへの出力を無効化                                 |
| `--check_interval <seconds>`    | ルール相関チェックの時間間隔（秒）を設定                            |
| `--log_path <path>`             | ログファイルのカスタムディレクトリパスを設定                          |
| `--verbose`                     | コンソールへの詳細ログ出力を有効化                                  |

  <div align="center"><img src="images/cui.png" width="600"></div>
  
### GUI使用法

1. 引数なしで`YAMAGoya.exe`を実行（または実行可能ファイルをダブルクリック）してGUIを起動します。
2. GUIは4つのメインタブを持つユーザーフレンドリーなインターフェースを提供します：

#### Main タブ
- **セッション状態表示**: 現在のETWセッション状態を色分けインジケーターで表示
- **ルールフォルダ選択**: 検知ルールを含むフォルダを参照・選択
- **Start/Stop Detection**: 監視操作を開始・終了する大きなボタン

#### Alert Monitoring タブ
- **リアルタイムアラート表示**: タイムスタンプ付きのセキュリティアラートのライブ監視
- **ログファイルアクセス**: 現在のログファイルへの素早いアクセス

#### Settings タブ
高度な検知オプションを設定：
- **Kill Process Mode**: 検知された悪意のあるプロセスを自動的に終了
- **Rule Format Selection**: 
  - Sigmaルールを使用（標準化された脅威検知）
  - カスタムYAMLルールを使用（カスタム相関ロジック）
- **YARA Memory Scanning**: メモリスキャンを有効化（デフォルト：1時間）
- **Logging Configuration**:
  - イベントログ: Windowsイベントログにアラートを保存
  - テキストログ: テキストファイルにアラートを保存
- **Custom ETW Session Name**: ETWセッション名を設定（デフォルト：YAMAGoya）

#### Help タブ

  <div align="center"><img src="images/gui.png" width="600"></div>

  <div align="center"><img src="images/gui2.png" width="600"></div>
  
---

## コマンドラインの例

### ETWセッションの開始

```bash
YAMAGoya.exe --session
```

### ETWセッションの停止

```bash
YAMAGoya.exe --stop
```

### 検知ルールの適用（YAML）

```bash
YAMAGoya.exe --session --detect .\rules --all --kill --verbose
```

### 検知ルールの適用（Sigma）

```bash
YAMAGoya.exe --session --sigma C:\sigma_rules --all
```

### メモリスキャンの有効化

```bash
YAMAGoya.exe --session --yara .\yara_rules --all
```

### 特定イベントタイプの監視

```bash
# プロセス作成・終了の監視
YAMAGoya.exe --session --detect .\rules --process --verbose

# DNSクエリの監視
YAMAGoya.exe --session --detect .\rules --dns --verbose

# PowerShellスクリプト実行の監視
YAMAGoya.exe --session --detect .\rules --powershell --verbose

# WMIコマンド実行の監視
YAMAGoya.exe --session --detect .\rules --wmi --verbose

# シェルイベントの監視（RunKey、ショートカットなど）
YAMAGoya.exe --session --detect .\rules --shell --verbose

# ネットワークアクティビティの監視
YAMAGoya.exe --session --detect .\rules --ipv4 --ipv6 --verbose

# ファイル・レジストリ操作の監視
YAMAGoya.exe --session --detect .\rules --file --delfile --registry --verbose
```

### ログ設定

```bash
# テキストログファイルを無効化、Windowsイベントログは保持
YAMAGoya.exe --session --detect .\rules --all --no_text_log

# Windowsイベントログを無効化、テキストログファイルは保持
YAMAGoya.exe --session --detect .\rules --all --no_event_log

# カスタムログファイルパスを設定
YAMAGoya.exe --session --detect .\rules --all --log_path "D:\Logs\YAMAGoya"
```

### 高度な設定

```bash
# カスタムETWセッション名
YAMAGoya.exe --session --session_name "ForensicSession" --detect .\rules --all

# ルールチェック間隔を15秒に設定
YAMAGoya.exe --session --detect .\rules --all --check_interval 15

# カスタムセッション名と自動プロセス終了を組み合わせた監視
YAMAGoya.exe --session --session_name "ThreatHunting" --detect .\rules --process --registry --file --kill
```

### オールインワンの例

```bash
# すべてのオプションを使用した包括的監視
YAMAGoya.exe --session --session_name "ComprehensiveMonitoring" --detect .\rules --all --kill --verbose --check_interval 30 --log_path "C:\Logs\YAMAGoya"
```

---

## Sigmaサポート

YAMAGoyaは、検知ルールを記述するための汎用シグネチャ形式である[Sigma](https://github.com/SigmaHQ/sigma)をサポートしています。`--sigma`または`-si`コマンドラインオプションを使用することで、YAMAGoyaのカスタムYAMLルールの代わりにSigmaルールを使用できます。

### サポートされるSigmaカテゴリ

以下の表は、現在YAMAGoyaでサポートされているSigmaルールカテゴリを示しています：

| Sigmaカテゴリ | サポート状況 | 
|----------------|:---------:|
| create_remote_thread | ✓ |
| create_stream_hash | - |
| dns_query | ✓ |
| driver_load | - |
| file_access | ✓ |
| file_block | - |
| file_change | - |
| file_delete | ✓ |
| file_event | ✓ |
| file_rename | - |
| image_load | ✓ |
| network_connection | ✓ |
| pipe_created | - |
| ps_classic_provider_start | - |
| ps_classic_start | - |
| ps_module | - |
| ps_script | ✓ |
| process_access | ✓ |
| process_creation | ✓ |
| process_tampering | - |
| raw_access_thread | - |
| registry_add | ✓ |
| registry_delete | ✓ |
| registry_event | ✓ |
| registry_set | ✓ |
| sysmon_error | - |
| sysmon_status | - |
| system | - |
| wmi_event | ✓ |
| webserver | - |

### SigmaからETWへのマッピング

YAMAGoyaはSigmaカテゴリを適切なETWプロバイダーとイベントIDに変換します。サポートされているカテゴリのマッピングは以下の通りです：

| Sigmaカテゴリ | ETWプロバイダー | イベントID |
|----------------|--------------|-----------|
| create_remote_thread | Microsoft-Windows-Kernel-Audit-API-Calls | 5 |
| dns_query | Microsoft-Windows-DNS-Client | 3000-3020 |
| file_access | Microsoft-Windows-Kernel-File | 10, 12, 30 |
| file_event | Microsoft-Windows-Kernel-File | 10, 11, 12, 30 |
| file_delete | Microsoft-Windows-Kernel-File | 11 |
| image_load | Microsoft-Windows-Kernel-Process | 5 |
| network_connection | Microsoft-Windows-Kernel-Network | 1-16, 18, 42, 43 |
| ps_script | Microsoft-Windows-PowerShell | 4104 |
| process_access | Microsoft-Windows-Kernel-Process | 1 |
| process_creation | Microsoft-Windows-Kernel-Process | 1 |
| registry_add | Microsoft-Windows-Kernel-Registry | 1 |
| registry_delete | Microsoft-Windows-Kernel-Registry | 3, 6 |
| registry_event | Microsoft-Windows-Kernel-Registry | 1-7 |
| registry_set | Microsoft-Windows-Kernel-Registry | 5 |
| wmi_event | Microsoft-Windows-WMI-Activity | 1-50 |

---

## YAMLルールファイルの作成

YAML形式で検知ルールを作成するには、以下のスキーマに従ってください。各ルールファイルには以下を含める必要があります：

- **rulename**: ルールの一意の名前
- **description**: ルールが検知する内容の簡潔な説明
- **rules**: ルール項目のリスト。各項目には以下を含める必要があります：
  - **ruletype**: ルールの種類（例：`regex`、`binary`など）
  - **target**: マッチするイベントカテゴリ。有効なターゲットは以下です：
    - **file**: ファイル作成イベント
    - **delfile**: ファイル削除イベント
    - **process**: プロセスイベント
    - **open**: OpenProcess
    - **load**: DLL読み込みイベント
    - **registry**: レジストリイベント
    - **dns**: DNSイベント
    - **ipv4**: IPv4ネットワークイベント
    - **ipv6**: IPv6ネットワークイベント
    - **shell**: シェル関連イベント（RunKey、ショートカット）
    - **powershell**: PowerShell実行イベント
    - **wmi**: WMIコマンド実行イベント
  - **rule**: マッチするパターンまたは値（正規表現ルールの場合は有効な正規表現）

YAMLルールファイルの例：

```yaml
rulename: "MalwareExecutionDetection"
description: "Detects suspicious malware execution patterns."
rules:
  - ruletype: "regex"
    target: "process"
    rule: "^malicious_exe\\.exe$"
  - ruletype: "regex"
    target: "file"
    rule: ".*\\.(exe|dll)$"
  - ruletype: "binary"
    target: "file"
    rule: "2E 65 78 65"
```

**手順：**

1. `.yaml`または`.yml`拡張子で新しいファイルを作成します。
2. サンプル構造をコピーしてカスタマイズします。
3. 指定したルールフォルダにファイルを保存します。

---

## 設定

- **`Config.cs`**:  
  - `sessionName`: デフォルトのETWセッション名
  - `isTextLog`と`logDirectory`: テキストログの有効化とログディレクトリの指定
  - `logDateFormat`: ログファイル名で使用される日付形式文字列（デフォルト：「yyyy-MM-dd」）
  - `logFileNameFormat`: ログファイルの命名パターン（デフォルト：「yamagoya_{0}.log」）
  - `isEventLog`と`eventLogSource`: Windowsイベントログロギングの有効化とソース名の設定
  - `checkInterval`: ルール相関と状態リセットに使用される時間間隔（秒）カスタムYAMLルール使用時に適用
  - `memoryScanInterval`: YARAメモリスキャン操作の時間間隔（時間）
  - `logLevel`: ログの詳細度を制御（Debug、Info、Warning、Error）

- **システムトレイ**:
  - アプリケーションを最小化するとシステムトレイに送られます
  - トレイアイコンをダブルクリックしてウィンドウを復元します
  - トレイアイコンを右クリックして「Open」と「Exit」オプションのあるコンテキストメニューを表示します

---

## 既知の制限事項・注意点

1. **管理者権限での実行**: ETWセッションの管理、Windowsイベントログへの書き込み、プロセスの終了などには管理者権限が必要です。
2. **パフォーマンスオーバーヘッド**: 複数のプロバイダーや大量のイベントボリュームを監視すると、大量のログ出力が発生する可能性があります。それに応じてルールを調整してください。
3. **ETW Bypass**: 高度なマルウェアはユーザーランドの検知方法を回避する可能性があります。カーネルレベルまたはネットワークベースのソリューションで補完することを検討してください。
4. **Sigmaカテゴリサポート**: 現在、すべてのSigmaカテゴリがサポートされているわけではありません。詳細については[サポートされるSigmaカテゴリ](#サポートされるsigmaカテゴリ)のセクションを参照してください。

---

## ライセンス

詳細については[LICENSE](LICENSE.txt)ファイルを参照してください。

---

## FAQ（よくある質問）

### 一般的な質問

**Q: YAMAGoyaはどのような種類のマルウェアを検知できますか？**  
A: YAMAGoyaは、ETWイベントを通じて追跡可能な疑わしい動作を示すファイルレスマルウェア、リモートアクセストロイの木馬、バックドア、その他の悪意のあるソフトウェアを含む、幅広いマルウェアを検知できます。検知範囲は設定するルールによって異なります。ただし、デフォルトではYAMAGoyaに検知するルールは設定されていないため、SigmaまたはYARAルールを準備する必要があります。

**Q: YAMAGoyaの実行はシステムパフォーマンスに影響しますか？**  
A: YAMAGoyaはパフォーマンスへの影響を最小限に抑えるように設計されていますが、複数のETWプロバイダーを同時に監視するとシステムリソースを消費する可能性があります。最小限のオーバーヘッドで最適なパフォーマンスを得るには、使用ケースに必要なイベントカテゴリのみを有効化することを検討してください。

**Q: YAMAGoyaはアンチウイルスソフトウェアを置き換えることができますか？**  
A: いいえ、YAMAGoyaは高度な脅威検知と分析のための補完的なツールとして意図されています。多層防御戦略の一部として、従来のアンチウイルスソリューションと併用することで最も効果的に機能します。

### 技術的な質問

**Q: ETWセッションを開始するときに「Failed to start the ETW session」エラーが発生します。どうすればよいですか？**  
A: YAMAGoyaはETWセッションを管理するために管理者権限を必要とします。管理者としてアプリケーションを実行してください（右クリック→管理者として実行）。

**Q: 誤検知を最小限に抑えるにはどうすればよいですか？**  
A: ルールを慎重かつ反復的に調整してください。より具体的なパターンから始めて、環境でテストし、段階的にルールを改良してください。Sigmaルールの場合は、リスク許容度に合わせて信頼度や重要度の閾値を調整することを検討してください。

**Q: YAMLとSigmaルール形式の違いは何ですか？**  
A: YAMAGoyaのカスタムYAMLルールは、異なるETWプロバイダー間での柔軟なイベント相関を可能にします。

**Q: 開始するためのサンプルルールはどこで見つけられますか？**  
A: [Sigma GitHubリポジトリ](https://github.com/SigmaHQ/sigma)と[YARA rule GitHubリポジトリ](https://github.com/InQuest/awesome-yara?#rules)では、コミュニティによって維持されているルールの広範なコレクションが提供されています。

**Q: YARAルールでのスキャン頻度はどのくらいにすべきですか？**  
A: デフォルトのスキャン間隔は1時間で、検知効果とシステムパフォーマンスのバランスを取っています。セキュリティ要件とシステム容量に基づいて調整してください。高リスク環境では、より頻繁なスキャンが有益な場合があります。
