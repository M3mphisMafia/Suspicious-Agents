# Third-party notices

Undertow Security's own code is under the [Apache License 2.0](LICENSE). It uses these third-party
components, each under its own license. None of them is copied into this repository; they are
installed at build time or loaded by the dashboard pages.

| Component | Used for | How it arrives | License |
| --- | --- | --- | --- |
| [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python) | The LLM judge, flood mode's pattern choice, the red-team agent | Installed into the judge's Lambda layer by `infra/build_judge_layer.sh` | MIT |
| [botocore / boto3](https://github.com/boto/botocore), [awscrt](https://github.com/awslabs/aws-crt-python) | AWS API calls; SigV4A signing for CloudFront KeyValueStore | Lambda runtime, plus the judge's layer | Apache 2.0 |
| [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 | The authenticator-app QR code on the sign-in page | Loaded by `dashboard/login.html` from cdnjs | MIT |
| [Space Grotesk](https://github.com/floriankarsten/space-grotesk), [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) | Dashboard typefaces | Loaded by `dashboard/index.html` from Google Fonts | SIL Open Font License 1.1 |
| pytest, cfn-lint, cryptography | Tests only | `pip install -e '.[test,aws]'` | MIT, MIT-0, Apache 2.0 / BSD |

AWS, Amazon CloudFront, AWS WAF and the other AWS service names are trademarks of Amazon.com, Inc.
Undertow Security is not affiliated with or endorsed by Amazon, and is not related to the Undertow
web server project.
