require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// 1. Endpoint Threat Intel / WHOIS Scanner via VirusTotal
app.post('/api/scan', async (req, res) => {
  try {
    let { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain wajib diisi!' });

    // Bersihkan input domain jika user memasukkan http:// atau https://
    domain = domain.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split('/')[0].trim();

    // Request ke API VirusTotal
    const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY
      }
    });

    const attr = vtResponse.data.data.attributes;
    const stats = attr.last_analysis_stats || {};

    const scanResult = {
      domain: domain,
      registrar: attr.registrar || 'N/A (Private/Unknown)',
      creation_date: attr.creation_date ? new Date(attr.creation_date * 1000).toLocaleDateString('id-ID') : 'N/A',
      reputation: attr.reputation || 0,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      status: (stats.malicious > 0 || stats.suspicious > 0) ? 'MALICIOUS / THREAT' : 'CLEAN / SAFE'
    };

    // Simpan hasil scan ke database Supabase
    await supabase.from('domain_logs').insert([{
      domain: scanResult.domain,
      status: scanResult.status,
      malicious_count: scanResult.malicious,
      harmless_count: scanResult.harmless
    }]);

    res.json(scanResult);

  } catch (err) {
    console.error('Error VT API:', err.response?.data || err.message);
    const msg = err.response?.status === 404 ? 'Domain tidak ditemukan di database VirusTotal.' : 'Gagal memproses analisis domain.';
    res.status(err.response?.status || 500).json({ error: msg });
  }
});

// 2. Endpoint Ambil Riwayat Scan
app.get('/api/history', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('domain_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(10);

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Cyber Threat Intel Engine running at http://localhost:${PORT}`);
});