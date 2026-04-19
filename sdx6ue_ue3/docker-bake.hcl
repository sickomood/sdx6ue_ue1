group "default" {
  targets = ["recipe"]
}

target "recipe" {
  context    = "."
  dockerfile = "Dockerfile"
  tags       = ["sickomood/recipe-service:latest"]
  platforms  = ["linux/amd64", "linux/arm64"]
}
