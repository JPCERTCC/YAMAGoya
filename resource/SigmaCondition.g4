grammar SigmaCondition;

// Parser rules
expr: expr OR expr             # OrExpr
    | expr AND expr            # AndExpr
    | NOT expr                 # NotExpr
    | LPAREN expr RPAREN       # ParensExpr
    | count_expr               # CountExpr
    | ALL_OF_THEM              # AllOfThemExpr
    | IDENTIFIER               # IdentifierExpr
    ;

// Special numeric count expression
count_expr
    : NUMBER OF (THEM | IDENTIFIER WILDCARD?)
    ;

// Lexer rules
AND: 'and';
OR: 'or';
NOT: 'not';
LPAREN: '(';
RPAREN: ')';

ALL_OF_THEM: 'all of them';
THEM: 'them';
OF: 'of';

NUMBER: [0-9]+;
IDENTIFIER: [a-zA-Z_][a-zA-Z0-9_]*;
WILDCARD: '*';

// Whitespace
WS: [ \t\r\n]+ -> skip;
