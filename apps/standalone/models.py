def gateway_config(model, base_url):
    """Pi custom-provider contract: explicitly select Chat Completions, never Responses."""
    return {'providers': {'fouryi': {'api': 'openai-completions', 'baseUrl': base_url,
        'apiKey': 'OPENAI_API_KEY', 'models': [{'id': model, 'name': model, 'reasoning': False,
        'input': ['text'], 'contextWindow': 128000, 'maxTokens': 16384,
        'cost': {'input': 0, 'output': 0, 'cacheRead': 0, 'cacheWrite': 0},
        'compat': {'supportsDeveloperRole': False, 'supportsReasoningEffort': False,
                   'supportsStore': False}}]}}}
