/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CONFIGPARSER_H
#define SQUID_CONFIGPARSER_H

#include "acl/forward.h"
#include "sbuf/forward.h"
#include "SquidString.h"

#include <queue>
#include <stack>
#include <string>

class wordlist;

class ConfigParser;
typedef char *(ConfigParser::*TokenExtractor)();

namespace Configuration {

/// A single-pass input iterator reading tokens from a configuration line.
/// The first read is performed when the object is constructed,
/// further reads are done by increment operators.
class TokensIterator : public std::iterator<std::input_iterator_tag, char *>
{
public:

    explicit TokensIterator(ConfigParser *parser, const TokenExtractor method):
        parser_(parser), method_(method), current_(parser ? (parser_->*method_)() : nullptr)
    {}

    value_type operator*() { return current_; }

    TokensIterator& operator++() {
        assert(method_);
        current_ = (parser_->*method_)();
        return *this;
    }

    TokensIterator operator++(int) {
        TokensIterator tmp = *this;
        ++(*this);
        return tmp;
    }

    bool operator==(const TokensIterator& other) const { return current_ == other.current_; }
    bool operator!=(const TokensIterator& other) const { return current_ != other.current_; }

private:
    ConfigParser *parser_;
    TokenExtractor method_; ///< a ConfigParser method for extracting tokens
    value_type current_; ///< a token returned by method_ (or nil)
};

/// a [begin, end) sequence of configuration tokens
class Tokens
{
public:
    Tokens(ConfigParser *parser, const TokenExtractor method, const char *desc, const bool mayBeEmpty):
        parser_(parser), method_(method), description_(desc), emptyAllowed_(mayBeEmpty) {}
    TokensIterator begin() const;
    TokensIterator end() const { return TokensIterator(nullptr, nullptr); }

private:
    ConfigParser *parser_;
    TokenExtractor method_; ///< a ConfigParser method for extracting tokens
    const char *description_; ///< a description of the expected token(s)
    const bool emptyAllowed_; ///< whether this sequence is allowed to have no elements
};

/// Is thrown when a required token is missing
class MissingTokenException : public TextException { using TextException::TextException; };

}

/**
 * Limit to how long any given config line may be.
 * This affects squid.conf and all included files.
 *
 * Behaviour when setting larger than 2KB is unknown.
 * The config parser read mechanism can cope, but the other systems
 * receiving the data from its buffers on such lines may not.
 */
#define CONFIG_LINE_LIMIT   2048

/**
 * A configuration file Parser. Instances of this class track
 * parsing state and perform tokenisation. Syntax is currently
 * taken care of outside this class.
 *
 * One reason for this class is to allow testing of configuration
 * using modules without linking cache_cf.o in - because that drags
 * in all of squid by reference. Instead the tokeniser only is
 * brought in.
 */
class ConfigParser
{

public:
    /**
     * Parsed tokens type: simple tokens, quoted tokens or function
     * like parameters.
     */
    enum TokenType {SimpleToken, QuotedToken, FunctionParameters};

    void destruct();

    /// stops parsing the current configuration directive
    void closeDirective();

    /// rejects configuration due to a repeated directive
    void rejectDuplicateDirective();

    /// extracts and returns a required token
    SBuf token(const char *expectedTokenDescription);

    /// extracts an optional key=value token or returns false
    /// rejects configurations with empty keys or empty values
    /// key and value have lifetime of the current line/directive
    bool optionalKvPair(char * &key, char * &value);

    /// either extracts the given (optional) token or returns false
    bool skipOptional(const char *keyword);

    /// parses an [if [!]<acl>...] construct
    Acl::Tree *optionalAclList();

    static void ParseUShort(unsigned short *var);
    static void ParseBool(bool *var);
    static const char *QuoteString(const String &var);
    static void ParseWordList(wordlist **list);

    /**
     * Returns the body of the next element. The element is either a token or
     * a quoted string with optional escape sequences and/or macros. The body
     * of a quoted string element does not include quotes or escape sequences.
     * Future code will want to see Elements and not just their bodies.
     */
    static char *NextToken();

    /**
     * Parse the next token as a regex pattern. The regex patterns are non quoted
     * tokens.
     */
    static char *RegexPattern();

    /**
     * Parse the next token with support for quoted values enabled even if
     * the configuration_includes_quoted_values is set to off
     */
    static char *NextQuotedToken();

    /// \return true if the last parsed token was quoted
    static bool LastTokenWasQuoted() {return (LastTokenType == ConfigParser::QuotedToken);}

    /**
     * \return the next quoted string or the raw string data until the end of line.
     * This method allows %macros in unquoted strings to keep compatibility
     * for the logformat option.
     */
    static char *NextQuotedOrToEol();

    /**
     * the next key value pair which must be separated by "="
     * \return true on success, false otherwise
     */
    static bool NextKvPair(char * &key, char * &value);

    /**
     * Preview the next token. The next NextToken() call
     * will return the same token.
     * On parse error (eg invalid characters in token) will return an
     * error message as token.
     */
    static char *PeekAtToken();

    /**
     * The next NextToken call will return the token as next element
     * It can be used repeatedly to add more than one tokens in a FIFO list.
     */
    static void TokenPutBack(const char *token);

    /// Set the configuration file line to parse.
    static void SetCfgLine(char *line);

    /// Allow %macros inside quoted strings
    static void EnableMacros() {AllowMacros_ = true;}

    /// Do not allow %macros inside quoted strings
    static void DisableMacros() {AllowMacros_ = false;}

    static SBuf CurrentLocation();

    /// \returns global LegacyParser
    static ConfigParser &Current();

    // The methods below support reading configuration tokens from external files.
    // External file names can be passed either via quoted tokens ('configuration_includes_quoted_values'
    // is off) or via parameters("/path/filename") syntax.
    /// \returns a non-empty ACL parameter sequence
    Configuration::Tokens requiredAclTokens(const char *description) { return Configuration::Tokens(this, &ConfigParser::aclToken, description, false); }
    /// \returns a possibly empty ACL parameter sequence
    Configuration::Tokens optionalAclTokens(const char *description) { return Configuration::Tokens(this, &ConfigParser::aclToken, description, true); }
    /// \returns a non-empty ACL parameter sequence, with elements as regex patterns
    Configuration::Tokens requiredAclRegexTokens(const char *description) { return Configuration::Tokens(this, &ConfigParser::regexAclToken, description, false); }
    /// \returns a non-nil ACL parameter
    const char *requiredAclToken(const char *description) { return *requiredAclTokens(description).begin(); }
    /// \returns a possibly nil ACL parameter
    const char *optionalAclToken(const char *description) { return *optionalAclTokens(description).begin(); }

    /// configuration_includes_quoted_values in squid.conf
    static bool RecognizeQuotedValues;

    /**
     * Strict syntax mode. Does not allow not alphanumeric characters in unquoted tokens.
     * Controlled by the  configuration_includes_quoted_values in squid.conf but remains
     * false when the the legacy ConfigParser::NextQuotedToken() call forces
     * RecognizeQuotedValues to be temporary true.
     */
    static bool StrictMode;

protected:
    /**
     * Class used to store required information for the current
     * configuration file.
     */
    class CfgFile
    {
    public:
        CfgFile(): wordFile(NULL), parsePos(NULL), lineNo(0) { parseBuffer[0] = '\0';}
        ~CfgFile();
        /// True if the configuration file is open
        bool isOpen() {return wordFile != NULL;}

        /**
         * Open the file given by 'path' and initializes the CfgFile object
         * to start parsing
         */
        bool startParse(char *path);

        /**
         * Do the next parsing step:
         * reads the next line from file if required.
         * \return the body of next element or a NULL pointer if there are no more token elements in the file.
         * \param type will be filled with the ConfigParse::TokenType for any element found, or left unchanged if NULL is returned.
         */
        char *parse(TokenType &type);

    private:
        bool getFileLine();   ///< Read the next line from the file
        /**
         * Return the body of the next element. If the wasQuoted is given
         * set to true if the element was quoted.
         */
        char *nextElement(TokenType &type);
        FILE *wordFile; ///< Pointer to the file.
        char parseBuffer[CONFIG_LINE_LIMIT]; ///< Temporary buffer to store data to parse
        const char *parsePos; ///< The next element position in parseBuffer string
    public:
        std::string filePath; ///< The file path
        std::string currentLine; ///< The current line to parse
        int lineNo; ///< Current line number
    };

    /// parses the next ACL parameter
    char *aclToken();
    /// parses the next ACL parameter as a regex pattern
    char *regexAclToken();

    /// Return the last TokenPutBack() queued element or NULL if none exist
    static char *Undo();

    /**
     * Unquotes the token, which must be quoted.
     * \param next if it is not NULL, it is set after the end of token.
     */
    static char *UnQuote(const char *token, const char **next = NULL);

    /**
     * Does the real tokens parsing job: Ignore comments, unquote an
     * element if required.
     * \return the next token, or NULL if there are no available tokens in the nextToken string.
     * \param nextToken updated to point to the pos after parsed token.
     * \param type      The token type
     */
    static char *TokenParse(const char * &nextToken, TokenType &type);

    /// Wrapper method for TokenParse.
    static char *NextElement(TokenType &type);
    static std::stack<CfgFile *> CfgFiles; ///< The stack of open cfg files
    static TokenType LastTokenType; ///< The type of last parsed element
    static const char *CfgLine; ///< The current line to parse
    static const char *CfgPos; ///< Pointer to the next element in cfgLine string
    static std::queue<char *> CfgLineTokens_; ///< Store the list of tokens for current configuration line
    static std::queue<std::string> Undo_; ///< The list with TokenPutBack() queued elements
    static bool AllowMacros_;
    static bool ParseQuotedOrToEol_; ///< The next tokens will be handled as quoted or to_eol token
    static bool RecognizeQuotedPair_; ///< The next tokens may contain quoted-pair (\-escaped) characters
    static bool PreviewMode_; ///< The next token will not popped from cfg files, will just previewd.
    static bool ParseKvPair_; ///<The next token will be handled as kv-pair token
    static enum ParsingStates {atParseKey, atParseValue} KvPairState_; ///< Parsing state while parsing kv-pair tokens
};

int parseConfigFile(const char *file_name);

#endif /* SQUID_CONFIGPARSER_H */

