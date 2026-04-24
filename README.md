# totp-client-for-dev

開発・検証用途の、ブラウザ内で完結する静的 TOTP クライアントです。Secret Key を入力すると 30 秒ごとにワンタイムパスワードを生成し、複数アカウントを `localStorage` に保存できます。バックエンド・外部 API・CDN を一切使わないため、GitHub Pages にそのままデプロイできます。

## 概要

- RFC 6238 準拠の TOTP を Web Crypto API で生成
- Base32 Secret Key / `otpauth://` URI の両方に対応
- アカウントをブラウザの `localStorage` に保存(キー: `dev_totp_accounts_v1`)
- 単一ページ構成: `index.html` + `style.css` + `app.js`
- npm / ビルド不要、外部ネットワーク不要(CSP で `connect-src 'none'` を宣言)

## GitHub Pages での公開方法

1. このリポジトリを GitHub にプッシュします。
2. リポジトリの **Settings → Pages** を開きます。
3. **Source** を `Deploy from a branch` にし、ブランチ(例: `main`)と `/ (root)` を選択します。
4. 数十秒後、`https://<username>.github.io/<repo>/` でアクセスできるようになります。

Jekyll によるファイルフィルタを無効化するために、リポジトリ直下に空の `.nojekyll` を置いています。

## ローカルでの確認

この種の静的ページはそのままファイルを開くと `file://` プロトコルの制約に当たることがあるため、簡易サーバーで動作確認してください。

```bash
python3 -m http.server 8000
# http://localhost:8000/ を開く
```

## 使い方

1. **Issuer**(例: `MyDevApp`)と **Account name**(例: `alice@example.com`)を入力します。
2. **Secret Key** を入力します。以下の形式に対応しています。
   - 生の Base32 文字列(スペース・ハイフン・小文字は自動で正規化されます)
   - `otpauth://totp/...` URI(貼り付けると Secret / Issuer / Account / digits / period / algorithm を自動抽出します)
3. **追加** を押すと、一覧に現れ 30 秒ごとに自動でコードが更新されます。
4. コードをクリックするか **コピー** ボタンで、数字のみ(空白除去)がクリップボードにコピーされます。
5. **デモ用サンプルを追加** を押すと、RFC 6238 のテストベクトル(Secret = ASCII `12345678901234567890`)のアカウントが追加されます。これは動作確認用であり、本番用途では絶対に使用しないでください。

## セキュリティ上の注意

- **本ツールは開発・検証用途のみを想定しています。**
- Secret Key はブラウザの `localStorage` に **平文** で保存されます。
- 共有 PC や本番アカウント(業務で使う認証、個人の重要アカウント等)では使用しないでください。
- 同一ドメイン / 同一オリジンで動作する他のスクリプトや拡張機能は `localStorage` を読み取り可能です。
- `index.html` に CSP を設定し、`connect-src 'none'`・`object-src 'none'`・インラインスクリプト不許可としています。ただしブラウザ拡張の挙動までは制限できません。
- TOTP の生成はすべてブラウザ内で完結し、Secret Key はサーバーに送信されません。

## データの削除方法

- 個別アカウント: 各カードの **削除** ボタン。
- 全削除: **全データ削除** ボタン(`localStorage` 内の `dev_totp_accounts_v1` を削除します)。
- 手動での削除: ブラウザの DevTools → Application → Local Storage → 該当オリジン → `dev_totp_accounts_v1` を削除。

## 対応仕様

- RFC 6238 (TOTP)
- HMAC-SHA1(デフォルト / `otpauth://` 経由で SHA-256 / SHA-512 も可)
- Base32 (RFC 4648)
- 6 digits(`otpauth://` 経由で他の digits も許容)
- 30 sec period(`otpauth://` 経由で他の period も許容)

## ファイル構成

```
index.html    # HTML 本体(CSP 設定含む)
style.css     # ダークテーマの UI
app.js        # TOTP ロジック + UI ロジック
README.md     # このファイル
.nojekyll     # GitHub Pages の Jekyll ビルド無効化用
```

## ライセンス

本リポジトリの `LICENSE` を参照してください。
