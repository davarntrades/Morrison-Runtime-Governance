// Shared motion engine for the advert-style cuts.
// A page defines scenes with scene(dur, draw, cues) and then calls start().
// Every frame is a pure function of time: render(t). ?format=v renders 9:16.
const VERT=new URLSearchParams(location.search).get('format')==='v';
const W=VERT?720:1280,H=VERT?1280:720,S=1.5,M=VERT?40:70; // design space, scale, side margin
const P=(h,v)=>VERT?v:h;
const c=document.getElementById('c');c.width=W*S;c.height=H*S;
let x=c.getContext('2d');
const BG='#07090d',GRID='#131a23',INK='#f1f5f9',SOFT='#c3cbd6',DIM='#8b96a5',LINE='#2a3441',PANEL='#0f151d',
      ACC='#4cc2ff',RED='#ff4d4d',AMB='#ffb224',GRN='#3ddc84';
const clamp=(v,a=0,b=1)=>Math.min(b,Math.max(a,v));
const prog=(t,s,d)=>clamp((t-s)/d);
const eo=p=>1-Math.pow(1-p,3), eio=p=>p<.5?4*p*p*p:1-Math.pow(-2*p+2,3)/2, e5=p=>1-Math.pow(1-p,5);
const lerp=(a,b,p)=>a+(b-a)*p;
let GA=1;
const A=a=>{x.globalAlpha=clamp(a)*GA};
const font=(size,w,mono)=>`${w} ${size}px ${mono?'"DejaVu Sans Mono",monospace':'"DejaVu Sans",sans-serif'}`;
function TW(s,size,w=700,mono=false,ls=0){x.font=font(size,w,mono);x.letterSpacing=ls+'px';const r=x.measureText(s).width;x.letterSpacing='0px';return r}
function T(s,px,py,o={}){const{size=20,col=INK,w=700,align='center',a=1,mono=false,ls=0}=o;if(a<=0||!s)return;
  A(a);x.fillStyle=col;x.font=font(size,w,mono);x.textAlign=align;x.textBaseline='middle';x.letterSpacing=ls+'px';x.fillText(s,px,py);x.letterSpacing='0px'}
// chromatic-split text: red/cyan fringes offset by `amt` px
function G(s,px,py,o={},amt=0){if(amt>.3){x.save();x.globalCompositeOperation='lighter';
  T(s,px-amt,py,{...o,col:'#ff2a55',a:(o.a??1)*.8});T(s,px+amt,py+amt*.3,{...o,col:'#22d3ff',a:(o.a??1)*.8});x.restore()}T(s,px,py,o)}
// multi-line block centred on (cx,cy) (or left-aligned at cx); shrinks to fit maxW
function TL(lines,cx,cy,o={}){let size=o.size||20;const maxW=o.maxW||W-2*M;
  for(const l of lines){const w=TW(l,size,o.w??700,o.mono,o.ls||0);if(w>maxW)size*=maxW/w}
  const lh=size*(o.lh||1.2),y0=cy-(lines.length-1)*lh/2;lines.forEach((l,i)=>G(l,cx,y0+i*lh,{...o,size},o.glitch||0))}
const typedLines=(lines,p)=>{let n=Math.floor(lines.join('').length*clamp(p));return lines.map(l=>{const s=l.slice(0,Math.max(0,n));n-=l.length;return s})};
function RR(px,py,w,h,r,o={}){const{fill,stroke,lw=2,a=1}=o;A(a);x.beginPath();x.roundRect(px,py,w,h,r);
  if(fill){x.fillStyle=fill;x.fill()}if(stroke){x.strokeStyle=stroke;x.lineWidth=lw;x.stroke()}}
function LN(x1,y1,x2,y2,o={}){const{col=LINE,lw=2,a=1}=o;A(a);x.strokeStyle=col;x.lineWidth=lw;x.lineCap='round';x.beginPath();x.moveTo(x1,y1);x.lineTo(x2,y2);x.stroke()}
const chipW=(label,size)=>TW(label,size,700,true)+34;
function chip(label,cx,cy,col,o={}){const{a=1,sc=1,sy=1,size=18,solid=true}=o;if(a<=0)return;
  const w=chipW(label,size),h=size+18;x.save();x.translate(cx,cy);x.scale(sc,sc*sy);
  RR(-w/2,-h/2,w,h,h/2,solid?{fill:col,a}:{stroke:col,lw:2.5,a,fill:BG});T(label,0,1,{size,col:solid?BG:col,mono:true,a});x.restore()}
function glowR(px,py,r,col,a){if(a<=0)return;A(a);const g=x.createRadialGradient(px,py,0,px,py,r);g.addColorStop(0,col);g.addColorStop(1,'rgba(0,0,0,0)');x.fillStyle=g;x.fillRect(px-r,py-r,2*r,2*r)}
// slam-in: scale from big to 1
const slam=(t,s,d=.28)=>{const p=prog(t,s,d);return{p,a:eo(prog(t,s,d*.5)),sc:p<=0?3:lerp(2.6,1,e5(p))}};
function scaled(px,py,sc,fn){x.save();x.translate(px,py);x.scale(sc,sc);fn();x.restore()}
const shake=(t,s,d,amp)=>{const p=prog(t,s,d);if(p<=0||p>=1)return[0,0];const k=amp*Math.pow(1-p,2);return[Math.sin(t*97)*k,Math.cos(t*73)*k]};
const glitch=(t,s,d,amp)=>{const p=prog(t,s,d);return p>0&&p<1?amp*(1-p)*(.6+.4*Math.sin(t*140)):0};

const CUES=[];const scenes=[];let OFF=0,TOTAL=0;
// each scene: duration, draw(local t) returning {shake:[dx,dy], flash:[col,alpha], red:0..1}
function scene(dur,draw,cues=[]){scenes.push({t0:OFF,dur,draw});cues.forEach(([lt,k])=>CUES.push([+(OFF+lt).toFixed(3),k]));OFF+=dur}

const off=document.createElement('canvas').getContext('2d');
// run a scene's draw off-screen only to read its effects (shake/flash/red)
function probe(sc,lt){const real=x;let res;try{x=off;res=sc.draw(lt)||{}}finally{x=real}return res}
function render(t){
  x.setTransform(S,0,0,S,0,0);GA=1;x.globalAlpha=1;x.fillStyle=BG;x.fillRect(0,0,W,H);
  const sc=scenes.find(s=>t<s.t0+s.dur)||scenes[scenes.length-1],lt=t-sc.t0,fx=probe(sc,lt);
  x.fillStyle=GRID;for(let gx=0;gx<W+40;gx+=40)for(let gy=20;gy<H;gy+=40){x.beginPath();x.arc((gx+t*14)%(W+40),gy,1.5,0,7);x.fill()}
  const z=1+.035*clamp(lt/sc.dur); // slow push-in on every shot
  x.save();x.translate(W/2+(fx.shake?.[0]||0),H/2+(fx.shake?.[1]||0));x.scale(z,z);x.translate(-W/2,-H/2);
  GA=1-eio(prog(t,TOTAL-.5,.5));sc.draw(lt);x.restore();GA=1;x.globalAlpha=1;
  if(fx.red){A(.18*fx.red);x.fillStyle='#ff2040';x.fillRect(0,0,W,H);A(.07*fx.red);x.fillStyle='#000';for(let y=0;y<H;y+=3)x.fillRect(0,y,W,1);x.globalAlpha=1}
  if(fx.flash&&fx.flash[1]>0){A(fx.flash[1]*.55);x.fillStyle=fx.flash[0];x.fillRect(0,0,W,H);x.globalAlpha=1}
  const R=Math.max(W,H),v=x.createRadialGradient(W/2,H/2,R*.25,W/2,H/2,R*.75);v.addColorStop(0,'rgba(0,0,0,0)');v.addColorStop(1,'rgba(0,0,0,.55)');x.fillStyle=v;x.fillRect(0,0,W,H);
}
function start(){
  TOTAL=OFF;window.render=render;window.TOTAL=TOTAL;window.CUES=CUES.sort((a,b)=>a[0]-b[0]);
  if(!location.search.includes('render')){const st=performance.now();(function loop(){render(((performance.now()-st)/1000)%TOTAL);requestAnimationFrame(loop)})()}
  else render(0);
}
