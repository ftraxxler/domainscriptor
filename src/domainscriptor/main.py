from .cli_handler import argument_handler
from dotenv import load_dotenv


def main():
    load_dotenv()
    argument_handler()

if __name__ == "__main__":
    main()
