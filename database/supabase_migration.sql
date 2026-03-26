-- PhantomIDS: Supabase Database Migration
-- Execute this SQL in the Supabase SQL Editor.

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ====================================================================
-- 1. organizations (Registration Requests & Approved Orgs)
-- ====================================================================
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_name TEXT NOT NULL,
    contact_name TEXT NOT NULL,
    work_email TEXT UNIQUE NOT NULL,
    role TEXT,
    company_size TEXT,
    use_case TEXT,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    approved_at TIMESTAMP WITH TIME ZONE,
    hardware_dispatched BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ====================================================================
-- 2. org_credentials (Links Orgs to Supabase Auth Users)
-- ====================================================================
CREATE TABLE org_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    supabase_auth_user_id UUID UNIQUE NOT NULL, -- References auth.users(id)
    username TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ====================================================================
-- 3. hardware_devices (ESP32 Device Registry)
-- ====================================================================
CREATE TABLE hardware_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_serial TEXT UNIQUE NOT NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    firmware_version TEXT DEFAULT 'v1.0',
    assigned_at TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ====================================================================
-- 4. alert_logs (Every Detected Intrusion Event)
-- ====================================================================
CREATE TABLE alert_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id UUID REFERENCES hardware_devices(id) ON DELETE SET NULL,
    threat_ip TEXT NOT NULL,
    target_endpoint TEXT,
    payload TEXT,
    detection_method TEXT DEFAULT 'signature' CHECK (detection_method IN ('signature', 'anomaly')),
    severity TEXT DEFAULT 'high' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    synced_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ====================================================================
-- 5. threat_ips (IP Reputation Tracking & Banning)
-- ====================================================================
CREATE TABLE threat_ips (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    attack_count INTEGER DEFAULT 0,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE,
    is_banned BOOLEAN DEFAULT FALSE,
    banned_at TIMESTAMP WITH TIME ZONE,
    ban_method TEXT CHECK (ban_method IN ('automatic', 'manual', NULL)),
    
    -- Ensure an IP is only tracked once per organization
    UNIQUE(org_id, ip_address) 
);

-- ====================================================================
-- 6. admin_notes (Internal Notes Per Org)
-- ====================================================================
CREATE TABLE admin_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    note TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ====================================================================
-- Indexes for Performance
-- ====================================================================
CREATE INDEX idx_orgs_status ON organizations(status);
CREATE INDEX idx_alerts_org_id ON alert_logs(org_id);
CREATE INDEX idx_alerts_detected_at ON alert_logs(detected_at DESC);
CREATE INDEX idx_threats_org_id ON threat_ips(org_id);
CREATE INDEX idx_threats_banned ON threat_ips(is_banned);

-- ====================================================================
-- Row Level Security (RLS) setup
-- Requirements: Organizations only see their exact data. Admins see all.
-- ====================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardware_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_ips ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_notes ENABLE ROW LEVEL SECURITY;

-- 1. Organizations: View/Update your own row.
-- (Public can insert for registration)
CREATE POLICY "Public can register organizations" 
ON organizations FOR INSERT TO anon 
WITH CHECK (status = 'pending');

CREATE POLICY "Orgs view their own data" 
ON organizations FOR SELECT TO authenticated
USING (
    id IN (SELECT org_id FROM org_credentials WHERE supabase_auth_user_id = auth.uid())
);

CREATE POLICY "Orgs update their own data" 
ON organizations FOR UPDATE TO authenticated
USING (
    id IN (SELECT org_id FROM org_credentials WHERE supabase_auth_user_id = auth.uid())
);

-- 2. Org Credentials: View your own
CREATE POLICY "Orgs view own credentials" 
ON org_credentials FOR SELECT TO authenticated
USING (supabase_auth_user_id = auth.uid());

-- 3. Hardware Devices: View your own
CREATE POLICY "Orgs view own devices" 
ON hardware_devices FOR SELECT TO authenticated
USING (
    org_id IN (SELECT org_id FROM org_credentials WHERE supabase_auth_user_id = auth.uid())
);

-- 4. Alert Logs: View your own, API role inserts
-- Allow anonymous HTTP POST from Flask to insert alerts if it has org_id
CREATE POLICY "Anon can insert alerts"
ON alert_logs FOR INSERT TO anon
WITH CHECK (true);

CREATE POLICY "Orgs view own alerts" 
ON alert_logs FOR SELECT TO authenticated
USING (
    org_id IN (SELECT org_id FROM org_credentials WHERE supabase_auth_user_id = auth.uid())
);

-- 5. Threat IPs: View & Update your own (for manual bans)
CREATE POLICY "Anon can insert/update threats"
ON threat_ips FOR ALL TO anon
USING (true) WITH CHECK(true);

CREATE POLICY "Orgs view own threat IPs" 
ON threat_ips FOR SELECT TO authenticated
USING (
    org_id IN (SELECT org_id FROM org_credentials WHERE supabase_auth_user_id = auth.uid())
);

CREATE POLICY "Orgs update own threat IPs (bans)" 
ON threat_ips FOR UPDATE TO authenticated
USING (
    org_id IN (SELECT org_id FROM org_credentials WHERE supabase_auth_user_id = auth.uid())
);

-- 6. Admin Notes: Strictly no access to generic authenticated users.
-- The service_role key inherently bypasses RLS, so logic using it can manage this safely.

-- ====================================================================
-- Note: All Supabase Admin Panel inserts/updates are done using
-- the service_role key, bypassing these policies naturally.
-- ====================================================================

-- Final step: Enable Realtime on alert_logs so Dashboard gets push updates
ALTER PUBLICATION supabase_realtime ADD TABLE alert_logs;
