class NetwatchError(Exception):
    """ Base exception for all Netwatch Errors """
    pass

class ParserError(NetwatchError, ValueError):
    """ Raised specifically when a system call log line cannot be parsed"""
    def __init__(self, parser, message):
        self.parser = parser
        self.message = message
        super().__init__(f"[{self.parser.upper()} ERROR] {self.message}")

class LexerError(NetwatchError, ValueError):
    """ Raised specifically when lexical tokenizer fails"""
    pass