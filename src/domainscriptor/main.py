from .cli_handler import argument_handler
from .config import get_config
from .logging_setup import setup_logging, get_logger
from dotenv import load_dotenv


def main():
    load_dotenv()
    cfg = get_config()
    setup_logging(cfg.path("log_dir"), cfg.logging.level)
    get_logger().info("Domainscriptor starting")
    argument_handler()


if __name__ == "__main__":
    main()
