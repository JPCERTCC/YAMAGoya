using Antlr4.Runtime.Misc;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace YAMAGoya.Core
{
    internal sealed class SigmaConditionVisitorImpl : SigmaConditionBaseVisitor<string>
    {
        private readonly List<string> _selectors;

        public SigmaConditionVisitorImpl(List<string> selectors)
        {
            _selectors = selectors;
        }

        public override string VisitAllOfThemExpr([NotNull] SigmaConditionParser.AllOfThemExprContext context)
        {
            return "(" + string.Join(" AND ", _selectors) + ")";
        }

        public override string VisitCountExpr([NotNull] SigmaConditionParser.CountExprContext context)
        {
            int number = int.Parse(context.count_expr().NUMBER().GetText(), CultureInfo.InvariantCulture);
            var target = context.count_expr().GetChild(2).GetText();

            var matchedSelectors = target == "them"
                ? _selectors
                : target.EndsWith('*')
                    ? _selectors.Where(s => s.StartsWith(target.TrimEnd('*'), StringComparison.Ordinal)).ToList()
                    : _selectors.Where(s => s == target).ToList();

            var combinations = GetCombinations(matchedSelectors, number)
                .Select(comb => "(" + string.Join(" AND ", comb) + ")");

            return "(" + string.Join(" OR ", combinations) + ")";
        }

        private static IEnumerable<IEnumerable<T>> GetCombinations<T>(IEnumerable<T> items, int count)
        {
            if (count == 0)
                yield return Array.Empty<T>();
            else
            {
                int index = 0;
                foreach (var item in items)
                {
                    var remaining = items.Skip(index + 1);
                    foreach (var combination in GetCombinations(remaining, count - 1))
                        yield return new[] { item }.Concat(combination);
                    index++;
                }
            }
        }

        public override string VisitOrExpr([NotNull] SigmaConditionParser.OrExprContext context)
            => $"({Visit(context.expr(0))} OR {Visit(context.expr(1))})";

        public override string VisitAndExpr([NotNull] SigmaConditionParser.AndExprContext context)
            => $"({Visit(context.expr(0))} AND {Visit(context.expr(1))})";

        public override string VisitNotExpr([NotNull] SigmaConditionParser.NotExprContext context)
            => $"(NOT {Visit(context.expr())})";

        public override string VisitParensExpr([NotNull] SigmaConditionParser.ParensExprContext context)
            => $"({Visit(context.expr())})";

        public override string VisitIdentifierExpr([NotNull] SigmaConditionParser.IdentifierExprContext context)
            => context.IDENTIFIER().GetText();
    }
}
