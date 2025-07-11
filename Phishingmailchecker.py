import os
import email
from email import policy
import re
from dotenv import load_dotenv
import google.generativeai as genai
from google.colab import files # ファイルアップロードUIのために追加

# --- ここから修正箇所 ---
# %%writefile を使わずに、Pythonの機能で .env ファイルを作成する
# YOUR_API_KEY_HERE をご自身のキーに置き換えてください
api_key_content = 'GOOGLE_API_KEY="YOUR_API_KEY_HERE"'
with open("/content/.env", "w") as f:
    f.write(api_key_content)
# --- 修正箇所ここまで ---

# 環境変数を読み込む
load_dotenv()
print("環境構築とAPIキーの読み込みが完了しました。")
print("-" * 20)


# ==================================
# 2. ファイルアップロードUIと分析実行
# ==================================
api_key = os.getenv('GOOGLE_API_KEY')
if not api_key:
    print("APIキーが.envファイルに設定されていません。")
else:
    genai.configure(api_key=api_key)

    # --- ここからUI処理 ---
    print("分析したいメールファイル(.eml)をアップロードしてください。")
    uploaded = files.upload() # ファイルアップロードUIを表示

    if not uploaded:
        print("ファイルがアップロードされませんでした。処理を中断します。")
    else:
        # アップロードされたファイル名を取得
        file_path = list(uploaded.keys())[0]
        print(f"\nファイル '{file_path}' がアップロードされました。分析を開始します。")
        print("-" * 20)

        # --- ここから既存の分析処理 ---
        def extract_email_info(path):
            """emlファイルを安全に解析し、情報を抽出する"""
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    msg = email.message_from_file(f, policy=policy.default)

                headers = {
                    "Subject": msg.get("Subject", "N/A"), "From": msg.get("From", "N/A"),
                    "To": msg.get("To", "N/A"), "Return-Path": msg.get("Return-Path", "N/A"),
                    "Received": msg.get_all("Received", [])
                }
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        cdispo = str(part.get('Content-Disposition'))
                        if ctype == 'text/plain' and 'attachment' not in cdispo:
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                else:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

                urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
                return headers, body, urls

            except Exception as e:
                print(f"メールの解析中にエラーが発生しました: {e}")
                return None, None, None

        mail_headers, mail_body, mail_urls = extract_email_info(file_path)

        # --- ここからドメイン検索リンク表示処理 ---
        def extract_domain(email_address):
            """メールアドレスからドメイン部分だけを抽出"""
            if not email_address or "@" not in email_address:
                return None
            return email_address.split("@")[-1].strip(">").strip()

        from_domain = extract_domain(mail_headers.get("From"))
        return_path_domain = extract_domain(mail_headers.get("Return-Path"))
        search_urls = []
        if from_domain:
            search_urls.append(f"Fromドメイン検索: https://mgt.jp/#{from_domain}")
        if return_path_domain and return_path_domain != from_domain:
            search_urls.append(f"Return-Pathドメイン検索: https://mgt.jp/#{return_path_domain}")

        if search_urls:
            print("\n--- ドメイン情報検索リンク ---")
            for url in search_urls:
                print(url)
            print("-----------------------------\n")
        # --- ここまでドメイン検索リンク表示処理 ---

        # ドメイン検索リンクをプロンプト用に文字列化
        domain_links_text = "\n".join(search_urls) if search_urls else "該当なし"

        if mail_body:
            prompt = f"""
あなたは、フィッシングメールの検知を専門とする優秀なサイバーセキュリティアナリストです。
以下のメール情報から、フィッシングメールの可能性を分析してください。

判定結果として「安全」「不審」「フィッシング」のいずれかを明確に示し、その上で具体的な理由を箇条書きで説明してください。特に以下の点に注目してください。
- 送信元アドレス（From）とReturn-Pathの不一致
- 本文中の不自然な日本語や、過度に緊急性を煽る表現
- リンクの表示テキストと実際のURLの食い違い
- 無関係または不審なドメインへのリンク

---
## メールヘッダー
{mail_headers}

## 本文
{mail_body}

## 抽出されたURL
{mail_urls}
---

## 分析結果
"""
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = model.generate_content(prompt)
            print(response.text)
