// Adds extra CSS classes "even" and "odd" to .memberdecls to allow
// striped backgrounds.
function MemberDeclsStriper () {
    var counter = 0;
    
    this.stripe = function() {
        $(".memberdecls tbody").children().each(function(i) {
            
            // reset counter at every heading -> always start with even
            if ($(this).is(".heading")) {
                counter = 0;
            }

            // add extra classes
            if (counter % 2 == 1) {
                $(this).addClass("odd");
            }
            else {
                $(this).addClass("even");
            }

            // advance counter at every separator
            // this is the only way to reliably detect which table rows belong together
            if ($(this).is('[class^="separator"]')) {
                counter++;
            }
        });
    }
}

// execute the function
$(document).ready(new MemberDeclsStriper().stripe);
