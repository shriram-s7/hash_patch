resource "aws_apigatewayv2_api" "app" {
  name          = "app-api"
  protocol_type = "HTTP"
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST"]
    allow_headers = ["*"]
  }
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.app.id
  name        = "prod"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "app" {
  api_id           = aws_apigatewayv2_api.app.id
  integration_type = "HTTP_PROXY"
  integration_uri  = "https://payment-api.example.com"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "app" {
  api_id    = aws_apigatewayv2_api.app.id
  route_key = "GET /payments"
  target    = "integrations/${aws_apigatewayv2_integration.app.id}"
}