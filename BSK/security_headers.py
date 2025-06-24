class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Nagłówki bezpieczeństwa:
        response['X-Frame-Options'] = 'DENY'
        response['Content-Security-Policy'] = "default-src 'self'"
        response['X-Content-Type-Options'] = 'nosniff'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response