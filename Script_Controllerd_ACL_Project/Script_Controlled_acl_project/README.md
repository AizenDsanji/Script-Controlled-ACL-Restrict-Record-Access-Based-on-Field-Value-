# Naan Mudhalvan – Script-Controlled ACL Micro Project

A full-stack demonstration of the **Script-Controlled ACL – Restrict Record Access Based on Field Value** lab. The supplied lab specifies an `u_institution_details` table, EEE/ECE/CSE branch values, custom roles `bb1`–`bb4`, and READ/CREATE/WRITE/DELETE ACL behavior. The core outcome is record-level security across operations. 

## Features
- Modern responsive dashboard UI/UX
- JWT login and protected API
- SQLite database with automatic seed data
- Users: `admin`, `eeeuser`, `viewer`
- Roles: `bb1` READ, `bb2` CREATE, `bb3` WRITE, `bb4` DELETE
- Non-admin READ scope restricted to EEE records
- Admin can view all branches
- Server-side ACL checks for every CRUD operation
- Search, statistics, permission indicators, create/edit/delete modal
- Clear ACL denial messages

## Tech stack
Frontend: React + Vite + Lucide Icons
Backend: Node.js + Express + SQLite (`better-sqlite3`) + JWT + bcrypt

## Run locally
Requirements: Node.js 18+.

```bash
npm install
npm run install:all
npm run dev
```

Open `http://localhost:5173`.

Backend API runs on `http://localhost:5000`.

## Demo credentials
| User | Password | Access |
|---|---|---|
| admin | admin123 | Full access |
| eeeuser | eee123 | READ/CREATE/WRITE/DELETE for EEE scope |
| viewer | viewer123 | No ACL role; denied |

## Project mapping
- `u_institution_details` → `institution_details`
- Student Roll Number → `roll_number`
- Student Name → `student_name`
- Faculty Name → `faculty_name`
- Branch → `branch` with ECE/EEE/CSE
- Email → `email`
- Phone Number → `phone`
- Description → `description`

## ACL model
1. Admin bypasses ACL checks.
2. `bb1` grants READ; non-admin reads are filtered to EEE.
3. `bb2` grants CREATE.
4. `bb3` grants WRITE.
5. `bb4` grants DELETE.
6. Server-side checks prevent UI-only bypasses.

## Important
This is a standalone educational implementation inspired by the supplied ServiceNow lab. It does not require a ServiceNow instance. If your college submission specifically requires ServiceNow screenshots, recreate the same configuration in your assigned instance using the lab document.

## Production notes
Change `JWT_SECRET`, use HTTPS, move credentials to environment variables, and add audit logging before deploying publicly.
