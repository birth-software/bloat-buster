#include <analysis.h>

#define todo() trap()
#define analysis_error() trap()

void analyze(CompileUnit* restrict unit)
{
    let tld_ref = unit->first_tld;

    while (is_ref_valid(tld_ref))
    {
        let tld = top_level_declaration_pointer_from_reference(unit, tld_ref);

        switch (tld->id)
        {
            break; case TOP_LEVEL_DECLARATION_TYPE:
            {
                todo();
            }
            break; case TOP_LEVEL_DECLARATION_GLOBAL:
            {
                todo();
            }
            break; case TOP_LEVEL_DECLARATION_WHEN:
            {
                todo();
            }
        }

        tld_ref = tld->next;
    }
}
