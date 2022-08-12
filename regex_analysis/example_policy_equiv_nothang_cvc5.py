#!/usr/bin/env python

# A simple demonstration of the solving capabilities of the cvc5 strings solver
# through the Python API.
# In this example, we are trying find equivalence of formulas.
# F1: x \in R1 where R1 is the regular expression /sys([a-z]|[0-9][_/])*
# F2: x \in R2 where R2 is the regular expression /([a-z]|[0-9][_/])*
# Prove if F1->F2 or F2 -> F2
# In this above example, F1 -> F2 is valid as R2 is superset of R1
# while F2->F1 is not true. It is satisfiable but not valid
# To prove a formula, F, is valid, we prove NOT(F) is unsatisfiable.
# That is, NOT(F1->F2) is unsat. This implies F1->F2 is valid and hence proved.
##

import cvc5
from cvc5 import Kind


if __name__ == "__main__":
    slv = cvc5.Solver()
    # Set the logic
    slv.setLogic("QF_SLIA")
    # Produce models
    slv.setOption("produce-models", "true")
    # The option strings-exp is needed
    slv.setOption("strings-exp", "true")
    # Set output language to SMTLIB2
    slv.setOption("output-language", "smt2")

    # String type
    string = slv.getStringSort()


    # String variables
    x = slv.mkConst(string, "x")


    #Regular expression r1: /sys([a-z]|[0-9][_/])*
    #Regular expression r2: /([a-z]|[0-9][_/])*

    PATH_CHAR_SET = set('abcdefghijklmnopqrstuvwxyz0123456789_/')
    p = [slv.mkTerm(Kind.STRING_TO_REGEXP,
                 slv.mkString(v)) for v in PATH_CHAR_SET]
    t =  slv.mkTerm(Kind.REGEXP_UNION,*p)

    r1 = slv.mkTerm(Kind.REGEXP_CONCAT,
                    slv.mkTerm(Kind.STRING_TO_REGEXP,
                               slv.mkString("/sys")),
                    slv.mkTerm(Kind.REGEXP_STAR,
                               t))
    r2 = slv.mkTerm(Kind.REGEXP_CONCAT,
                    slv.mkTerm(Kind.STRING_TO_REGEXP,
                               slv.mkString("/")),
                    slv.mkTerm(Kind.REGEXP_STAR,
                               t))

    formula1 = slv.mkTerm(Kind.STRING_IN_REGEXP, x, r1)
    formula2 = slv.mkTerm(Kind.STRING_IN_REGEXP, x, r2)

    # Make a query
    q = slv.mkTerm(Kind.NOT, slv.mkTerm(Kind.IMPLIES,
                   formula1,
                   formula2))

    # check sat
    result = slv.checkSatAssuming(q)
    print("cvc5 reports:", q, "is", result)

    #if result:
    #    #print("x= ", slv.getModel(q))
    #    print("x = ", slv.getValue(x))
        #print(" s1.s2 =", slv.getValue(s))

