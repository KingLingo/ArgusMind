import type { Request, Response } from 'express';

type MainLlmState = {
  provider: string;
  model: string;
  /** 明文仅驻内存，响应中只返回掩码 */
  apiKey: string;
  baseUrl: string;
};

type AiConfigStore = {
  mainLlm: MainLlmState;
};

function maskApiKey(secret: string): string {
  if (!secret) return '';
  if (secret.length <= 8) return '********';
  return `${secret.slice(0, 4)}…${secret.slice(-4)}`;
}

let store: AiConfigStore = {
  mainLlm: {
    provider: 'OpenAI 兼容',
    model: 'gpt-4o',
    apiKey: 'sk-proj-mock-argus-demo-key-001',
    baseUrl: 'https://api.openai.com/v1',
  },
};

function toResponsePayload() {
  return {
    mainLlm: {
      provider: store.mainLlm.provider,
      model: store.mainLlm.model,
      baseUrl: store.mainLlm.baseUrl,
      apiKeyMasked: maskApiKey(store.mainLlm.apiKey),
    },
  };
}

export default {
  'GET /api/ai-config': (_req: Request, res: Response) => {
    res.json({ success: true, data: toResponsePayload() });
  },
  'POST /api/ai-config': (req: Request, res: Response) => {
    const b = req.body as {
      mainLlm?: Partial<{
        provider: string;
        model: string;
        baseUrl: string;
        apiKey: string;
      }>;
    };
    if (b.mainLlm) {
      const { provider, model, baseUrl, apiKey } = b.mainLlm;
      if (provider != null) store.mainLlm.provider = provider;
      if (model != null) store.mainLlm.model = model;
      if (baseUrl != null) store.mainLlm.baseUrl = baseUrl;
      if (apiKey != null && apiKey.trim() !== '') {
        store.mainLlm.apiKey = apiKey.trim();
      }
    }
    res.json({ success: true, data: toResponsePayload() });
  },
};
