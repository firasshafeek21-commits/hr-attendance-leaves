-- Run once on the private PostgreSQL database before importing employee records.
CREATE TABLE IF NOT EXISTS employees (
  employee_number TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  job_title TEXT
);
