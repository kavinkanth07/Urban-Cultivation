# Urban Cultivation 🌱

**Connecting farmers with unused urban land, without a middleman.**

A command-line platform built with **Python and MySQL**. Landowners list unused or empty plots with a monthly rent. Farmers browse them and send lease requests, and landowners approve or reject each one.
It began as our Class XII Computer Science investigatory project (CBSE, 2023–24) and has since been cleaned up, secured and tested for this repository.

## Why

India's number of cultivators fell by about 12 % between 2011 and 2019 (Ministry of Agriculture & Farmers' Welfare). The reasons include low profitability, land fragmentation and poor access to land. Meanwhile, many plots on the edges of cities lie unused.
This project explores a simple digital platform that connects the two groups directly. That cuts out brokers and supports local, sustainable food production.

## Features

| Landowner | Farmer |
|---|---|
| Register / log in with a password | Register / log in with a password |
| List a plot (name, location, size, monthly rent, contact) | Browse available plots with their rent |
| Edit or remove their plots | Request a lease for 1–120 months (total cost shown first) |
| See each plot's status: available, requests waiting, or leased to whom and until when | Track requests: waiting, approved, rejected |
| Approve or reject lease requests | Cancel a request, or end a lease early |

* Leases end automatically on their end date, and the plot becomes available again.
* The landowner's phone number is shown to a farmer only after their request is approved.
* Type `cancel` at any prompt to go back to the menu.

## Input validation

During our viva, the examiner pointed out that the original program accepted whatever the user typed. Every input is now checked against its real-world format. If it doesn't match, the program explains what's expected and asks again.

| Field | Rule |
|---|---|
| Name | 2–60 characters: letters, spaces, `.` `-` `'` (e.g. `S. Kavin Kumar`) |
| Aadhaar | 12 digits (spaces allowed), can't start with 0 or 1, and the last digit must match the **Verhoeff checksum** that every real Aadhaar number has |
| PAN | `AAAAA9999A` format. The 4th letter must be a valid holder type (`P` = person, `C` = company, …), and the digits can't be `0000` |
| Mobile | Indian 10-digit number starting with 6–9. `+91`, `0` and spaces are accepted and removed |
| Password | 8–64 characters, at least one letter and one digit; typed twice and hidden on screen |
| Land name / location | 3–60 / 3–100 characters, letters, numbers and normal address punctuation only |
| Land size | 0.01–1000 acres, up to 2 decimals |
| Monthly rent | ₹100 – ₹10,00,000, whole rupees (`5000`, `5,000` and `Rs. 5000` all work) |
| Lease length | 1–120 months |

## Security

* **Passwords** are stored only as salted PBKDF2-SHA256 hashes. After 3 wrong attempts you go back to the main menu, and the error never says whether the Aadhaar number or the password was wrong.
* **Aadhaar and PAN are never stored.** The database keeps only a keyed one-way fingerprint (HMAC-SHA256), which is enough to stop duplicate accounts, plus the last 4 Aadhaar digits for display (`XXXX XXXX 1234`).
* **No double leasing.** Approving a request locks the plot's row inside a transaction, so one plot can never be leased to two farmers at once.
* **Least privilege.** The app connects as a dedicated MySQL user that can only reach its own database, not as `root`.
* **No secrets in the code.** Database settings come from environment variables or are asked for at start-up. All queries use parameters (`%s`), so SQL injection isn't possible.

## User flow

The flowchart we designed for the original project shows the questions the platform asks to route users as farmers, landowners or interested participants:

<img src="docs/user_flowchart.png" width="600">

## Database design

```
landowner (landowner_id, name, aadhaar_hash, aadhaar_last4, pan_hash, contact, password_hash)
    │ 1
    │ owns
    │ n
land (land_id, landowner_id, name, contact, location, size_acres, monthly_rent, is_listed)
    │ 1
    │ requested through
    │ n
lease (lease_id, farmer_id, land_id, months, monthly_rent, status, start_date, end_date)
    │ n
    │ 1
farmer (farmer_id, name, aadhaar_hash, aadhaar_last4, pan_hash, contact, password_hash)
```

A lease's `status` moves from `pending` to `approved`, `rejected` or `cancelled`, and an approved lease becomes `ended` after its end date.
A plot is *available* when it is listed and has no approved lease. Full schema: [`schema.sql`](schema.sql).

## Run it

**Requirements:** Python 3.8+ and MySQL 8+ (MariaDB 10.4+ also works).

1. Install the connector:
   ```bash
   pip install -r requirements.txt
   ```
2. Open `schema.sql` and change `change-this-password` to a password of your choice. Then run it once as root. This creates the database, the tables and the `urban_app` user:
   ```bash
   mysql -u root -p < schema.sql
   ```
3. Start the program:
   ```bash
   python urban_cultivation.py
   ```
   It asks for the MySQL user (press Enter for `urban_app`) and the password you set in step 2.

To skip the questions, set these environment variables before running:

| Variable | Default |
|---|---|
| `DB_HOST` | `localhost` |
| `DB_PORT` | `3306` |
| `DB_USER` | *(asked; default `urban_app`)* |
| `DB_PASSWORD` | *(asked at start)* |
| `DB_NAME` | `urban_cultivation` |
| `APP_SECRET` | *(optional, see below)* |

**The secret key:** On its first run, the program creates a file called `.urban_secret`. It's used to fingerprint Aadhaar and PAN numbers, and `.gitignore` keeps it off GitHub. **Back it up:** if it's lost, existing users can no longer log in. You can also supply the key through the `APP_SECRET` environment variable instead.

## Sample run

```
=== Available Lands ===
  ID  Name                 Location                 Acres   Rent/month
   1  Rooftop Plot         Jayanagar, Bengaluru      0.50    Rs. 3,000
   2  Empty Plot           Hebbal, Bengaluru         1.25    Rs. 8,000
Enter the Land ID you want to lease: 2
For how many months? (1-120): 200
  ! Enter the number of months, from 1 to 120.
For how many months? (1-120): 12

'Empty Plot' in Hebbal, Bengaluru (1.25 acres)
Rs. 8,000/month x 12 month(s) = Rs. 96,000 in total
Send the lease request? (yes/no): yes
Request sent! The landowner will approve or reject it - check 'My leases'.
```

The full transcript is in [`docs/sample_run.txt`](docs/sample_run.txt). It covers a landowner listing plots, a farmer sending a request, the landowner approving it, and examples of rejected inputs. All data there is made up.

## What changed from the school version

* Removed the hard-coded database password, and switched the app to its own MySQL user instead of `root`
* Added the missing functions, role-based menus and a working logout
* Replaced Aadhaar + PAN login with password login, and stopped storing Aadhaar and PAN in plain text
* Added strict format checks for every input (see [Input validation](#input-validation))
* Leasing no longer erases the landowner (the original set `landowner_id` to `NULL`). Leases are now separate requests with a rent, a length, and landowner approval.
* Landowners can edit and remove plots. Farmers can cancel requests and end leases.
* Database errors and Ctrl+C no longer crash the program

## Limitations and ideas

* Aadhaar numbers are checked only for format and checksum. A real system would verify identity with UIDAI's OTP-based e-KYC and follow India's Digital Personal Data Protection Act, 2023.
* There is no "forgot password" option yet.
* Command-line only. A web or mobile front end in regional languages would suit the target users better.
* Ideas: search by location or price, soil and water information, rent payment records, and links to government agriculture schemes.

## Team

Class XII, Presidency School, Bangalore North (2023–24)
**P R Kavinkanth** · Niharika · Rochan

## License

[MIT](LICENSE)
