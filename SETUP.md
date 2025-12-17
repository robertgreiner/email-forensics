# Gmail API Domain-Wide Delegation Setup

This guide walks you through setting up domain-wide delegation to access Gmail headers.

## Step 1: Google Cloud Console Setup

### 1.1 Create or Select a Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Note the **Project ID**

### 1.2 Enable Gmail API
1. Go to **APIs & Services** > **Library**
2. Search for "Gmail API"
3. Click **Enable**

### 1.3 Create Service Account
1. Go to **APIs & Services** > **Credentials**
2. Click **Create Credentials** > **Service Account**
3. Fill in:
   - Service account name: `email-forensics`
   - Service account ID: `email-forensics` (auto-filled)
4. Click **Create and Continue**
5. Skip the optional steps, click **Done**

### 1.4 Generate Service Account Key
1. Click on the service account you just created
2. Go to **Keys** tab
3. Click **Add Key** > **Create new key**
4. Select **JSON** format
5. Click **Create**
6. Save the downloaded file as `service-account-key.json` in this directory

### 1.5 Note the Service Account Email
The service account email looks like:
```
email-forensics@YOUR-PROJECT-ID.iam.gserviceaccount.com
```
You'll need this for the Admin Console setup.

---

## Step 2: Google Workspace Admin Console Setup

### 2.1 Enable Domain-Wide Delegation
1. Go to [Google Admin Console](https://admin.google.com/)
2. Navigate to **Security** > **Access and data control** > **API controls**
3. In the **Domain wide delegation** section, click **Manage Domain Wide Delegation**
4. Click **Add new**
5. Enter:
   - **Client ID**: The numeric client ID from your service account
     (find this in Cloud Console > IAM > Service Accounts > click your account > copy the "Unique ID")
   - **OAuth Scopes**:
     ```
     https://www.googleapis.com/auth/gmail.readonly
     ```
6. Click **Authorize**

### Finding the Client ID
1. In Google Cloud Console, go to **IAM & Admin** > **Service Accounts**
2. Click on your service account
3. Copy the **Unique ID** (a long numeric string like `102938475629384756283`)

---

## Step 3: Install Dependencies

```bash
cd /home/robert/Work/email-forensics
pip install -r requirements.txt
```

---

## Step 4: Run the Script

```bash
python get_email_headers.py
```

---

## Troubleshooting

### "403 Forbidden" or "Delegation denied"
- Verify the Client ID in Admin Console matches the service account's Unique ID
- Ensure the OAuth scope is exactly: `https://www.googleapis.com/auth/gmail.readonly`
- Wait 5-10 minutes after adding delegation (propagation delay)

### "User not found" or "Invalid user"
- Confirm the email address is correct
- The user must be in your Google Workspace domain

### "File not found: service-account-key.json"
- Ensure the JSON key file is in the same directory as the script
- Or update `SERVICE_ACCOUNT_FILE` path in the script

### "Gmail API has not been used" error
- Enable Gmail API in Cloud Console
- Wait a few minutes for it to propagate

---

## Security Notes

- Keep `service-account-key.json` secure - it grants access to user mailboxes
- Use the minimum required scope (`gmail.readonly`)
- Audit and revoke access when no longer needed
- Consider restricting the service account to specific OUs in Admin Console
