resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
}

# This references a non-existent target group
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.missing.arn
  }
}