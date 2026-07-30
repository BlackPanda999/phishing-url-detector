# 🔍 URL Features Documentation

## Feature List (25+)

| # | Feature | Type | Description |
|---|---------|------|-------------|
| 1 | `url_length` | float | Total URL character length |
| 2 | `hostname_length` | float | Hostname character length |
| 3 | `path_length` | float | URL path length |
| 4 | `query_length` | float | Query string length |
| 5 | `num_dots` | float | Count of dots in URL |
| 6 | `num_hyphens` | float | Count of hyphens in URL |
| 7 | `num_underscores` | float | Count of underscores in URL |
| 8 | `num_slashes` | float | Count of forward slashes |
| 9 | `num_at_symbols` | float | Count of @ symbols (redirect indicator) |
| 10 | `num_question_marks` | float | Count of ? characters |
| 11 | `num_ampersands` | float | Count of & characters |
| 12 | `num_equals` | float | Count of = characters |
| 13 | `num_digits` | float | Total digit count |
| 14 | `digit_ratio` | float | Ratio of digits to total length |
| 15 | `has_ip_address` | binary | URL uses IP instead of domain |
| 16 | `suspicious_tld` | binary | Uses known suspicious TLD |
| 17 | `uses_https` | binary | URL uses HTTPS protocol |
| 18 | `uses_http` | binary | URL uses HTTP protocol |
| 19 | `is_shortened` | binary | Uses URL shortening service |
| 20 | `num_suspicious_keywords` | float | Count of phishing keywords |
| 21 | `has_brand_name` | binary | Brand name in suspicious position |
| 22 | `num_subdomains` | float | Number of subdomains |
| 23 | `has_port` | binary | Non-standard port in URL |
| 24 | `has_encoded_chars` | binary | URL-encoded characters present |
| 25 | `num_encoded_chars` | float | Count of encoded characters |
| 26 | `has_double_slash_redirect` | binary | Double slash in path (redirect) |
| 27 | `has_hex_chars` | binary | Hex-encoded characters |
| 28 | `hostname_too_long` | binary | Hostname exceeds 50 chars |
| 29 | `url_too_long` | binary | URL exceeds 100 chars |

## Risk Scoring

| Risk Level | Score Range | Verdict |
|-----------|------------|---------|
| LOW | 0.0 - 0.39 | LEGITIMATE |
| MEDIUM | 0.4 - 0.69 | SUSPICIOUS |
| HIGH | 0.7 - 1.0 | PHISHING |

## Ensemble Weights

- ML Score: 60%
- Rule-Based Score: 40%
