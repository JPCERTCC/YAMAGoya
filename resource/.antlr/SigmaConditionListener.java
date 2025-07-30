// Generated from c:/Users/tomonaga/Documents/GitHub/YAMAGoya/resource/SigmaCondition.g4 by ANTLR 4.13.1
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link SigmaConditionParser}.
 */
public interface SigmaConditionListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by the {@code AndExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void enterAndExpr(SigmaConditionParser.AndExprContext ctx);
	/**
	 * Exit a parse tree produced by the {@code AndExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void exitAndExpr(SigmaConditionParser.AndExprContext ctx);
	/**
	 * Enter a parse tree produced by the {@code IdentifierExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void enterIdentifierExpr(SigmaConditionParser.IdentifierExprContext ctx);
	/**
	 * Exit a parse tree produced by the {@code IdentifierExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void exitIdentifierExpr(SigmaConditionParser.IdentifierExprContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ParensExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void enterParensExpr(SigmaConditionParser.ParensExprContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ParensExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void exitParensExpr(SigmaConditionParser.ParensExprContext ctx);
	/**
	 * Enter a parse tree produced by the {@code NotExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void enterNotExpr(SigmaConditionParser.NotExprContext ctx);
	/**
	 * Exit a parse tree produced by the {@code NotExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void exitNotExpr(SigmaConditionParser.NotExprContext ctx);
	/**
	 * Enter a parse tree produced by the {@code OrExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void enterOrExpr(SigmaConditionParser.OrExprContext ctx);
	/**
	 * Exit a parse tree produced by the {@code OrExpr}
	 * labeled alternative in {@link SigmaConditionParser#expr}.
	 * @param ctx the parse tree
	 */
	void exitOrExpr(SigmaConditionParser.OrExprContext ctx);
}