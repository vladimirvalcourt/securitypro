const https = require('https');
const http = require('http');
const chalk = require('chalk');

/**
 * Multi-LLM Provider System
 * Supports OpenAI, Anthropic (Claude), Google (Gemini), and Ollama
 */
class LLMHealer {
  constructor() {
    // Detect available providers based on environment variables
    this.providers = [];

    if (process.env.OPENAI_API_KEY) {
      this.providers.push({ name: 'OpenAI', generate: this.callOpenAI.bind(this) });
    }
    
    if (process.env.ANTHROPIC_API_KEY) {
      this.providers.push({ name: 'Anthropic', generate: this.callAnthropic.bind(this) });
    }
    
    if (process.env.GEMINI_API_KEY) {
      this.providers.push({ name: 'Gemini', generate: this.callGemini.bind(this) });
    }
    
    // Always add Ollama as a fallback. It will just fail quickly if not running locally.
    this.providers.push({ name: 'Ollama', generate: this.callOllama.bind(this) });

    // Pick the first available provider (prioritizes cloud APIs over local Ollama, unless only Ollama is available)
    this.activeProvider = this.providers[0];
  }

  isAvailable() {
    return this.activeProvider !== undefined;
  }

  async heal(finding, codeSnippet) {
    if (!this.isAvailable()) return null;

    console.log(chalk.cyan(`\n🤖 Asking AI (${this.activeProvider.name}) to heal: ${finding.title}...`));

    const prompt = `
You are an expert Application Security Engineer.
I have a security vulnerability in my code.
Vulnerability: ${finding.title}
Category: ${finding.category}
Remediation Advice: ${finding.remediation}

Here is the vulnerable code snippet:
\`\`\`
${codeSnippet}
\`\`\`

Please rewrite this code snippet to perfectly fix the vulnerability. 
Return ONLY the fixed code snippet without any markdown formatting or explanations. Do not include \`\`\` wrappers.
`;

    try {
      const response = await this.activeProvider.generate(prompt);
      return response.trim();
    } catch (error) {
      console.log(chalk.red(`   Failed to heal using ${this.activeProvider.name}: ${error.message}`));
      return null;
    }
  }

  async explain(finding) {
    if (!this.isAvailable()) return null;

    const prompt = `
You are an expert Application Security Engineer.
Please explain the following vulnerability to a junior developer in plain, simple English (maximum 2-3 sentences).
Explain WHY it is dangerous, and HOW to fix it conceptually.

Vulnerability: ${finding.title}
Category: ${finding.category}
Remediation Advice: ${finding.remediation}

Explanation:
`;

    try {
      const response = await this.activeProvider.generate(prompt);
      return response.trim();
    } catch (error) {
      return null;
    }
  }

  // --- Providers ---

  callOpenAI(prompt) {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.1
      });

      const options = {
        hostname: 'api.openai.com',
        path: '/v1/chat/completions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
          'Content-Length': Buffer.byteLength(payload)
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(data);
              resolve(parsed.choices[0].message.content);
            } catch (e) {
              reject(new Error('Failed to parse response'));
            }
          } else {
            reject(new Error(`API Error ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  callAnthropic(prompt) {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        model: 'claude-3-haiku-20240307',
        max_tokens: 1024,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.1
      });

      const options = {
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'Content-Length': Buffer.byteLength(payload)
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(data);
              resolve(parsed.content[0].text);
            } catch (e) {
              reject(new Error('Failed to parse response'));
            }
          } else {
            reject(new Error(`API Error ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  callGemini(prompt) {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1 }
      });

      const options = {
        hostname: 'generativelanguage.googleapis.com',
        path: `/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(data);
              resolve(parsed.candidates[0].content.parts[0].text);
            } catch (e) {
              reject(new Error('Failed to parse response'));
            }
          } else {
            reject(new Error(`API Error ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  callOllama(prompt) {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        model: process.env.OLLAMA_MODEL || 'llama3',
        prompt: prompt,
        stream: false,
        options: { temperature: 0.1 }
      });

      const url = new URL(process.env.OLLAMA_URL || 'http://localhost:11434/api/generate');
      
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      };

      // Ollama usually runs on HTTP, not HTTPS
      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(data);
              resolve(parsed.response);
            } catch (e) {
              reject(new Error('Failed to parse response'));
            }
          } else {
            reject(new Error(`API Error ${res.statusCode}`));
          }
        });
      });
      
      req.on('error', (e) => {
        reject(new Error('Ollama not reachable. Is the service running?'));
      });
      
      req.write(payload);
      req.end();
    });
  }
}

module.exports = LLMHealer;
