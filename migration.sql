ALTER TABLE registros ADD COLUMN IF NOT EXISTS anexos JSONB DEFAULT '[]'::jsonb;
