{
  "targets": [
    {
      "target_name": "parser",
      "type": "none",
      "sources": ["src/parser.c", "src/scanner.cc"],
      "include_dirs": ["<!(node -e \"require('tree-sitter')\")"]
    }
  ]
}

