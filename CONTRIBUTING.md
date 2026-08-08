# Contributing to k8s-health-monitor

Thank you for considering contributing!

## How to Contribute

1. Fork the repository
2. Create a feature branch (git checkout -b feature/my-feature)
3. Make your changes
4. Add tests if applicable
5. Run tests (python -m pytest tests/ -v)
6. Commit your changes (git commit -m 'Add my feature')
7. Push to the branch (git push origin feature/my-feature)
8. Open a Pull Request

## Development Setup

`ash
git clone https://github.com/Ankitavasudev/k8s-health-monitor.git
cd k8s-health-monitor
pip install -r requirements.txt
`

## Running Tests

`ash
python -m pytest tests/ -v
python -m pytest tests/ --cov=k8s_monitor
`

## Code Style

- Follow PEP 8
- Use type hints where possible
- Keep functions focused and small
- Add docstrings for public functions

## Reporting Issues

- Use GitHub Issues
- Include Python version and OS
- Provide steps to reproduce
- Include error messages

## Feature Requests

- Open an issue with the "enhancement" label
- Describe the use case
- Explain why it would be useful