-- desktop-auth lane: the machine name Agent Relay Desktop sends with a device
-- sign-in, shown on the approval page ("Agent Relay Desktop on <host>").
-- Display data only; it grants nothing.
ALTER TABLE selfhost_device_authorizations
  ADD COLUMN IF NOT EXISTS desktop_host_name text;
