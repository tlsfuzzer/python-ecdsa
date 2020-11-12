def pytest_addoption(parser):
    parser.addoption(
        "--fast", action="store_true", default=False, help="run tests fast"
    )
