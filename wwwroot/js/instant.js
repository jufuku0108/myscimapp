window.onload = function(){

    
    let urlToPreload;
    let mouseOverTimer;
    let lastTouchTimestamp;
    
    const prefetcher = document.createElement('link');
    const isSupported = prefetcher.relList && prefetcher.relList.supports && prefetcher.relList.supports('prefetch');
    const allowQueryString = 'instantQueryString' in document.body.dataset;
    
    if(isSupported) {
        prefetcher.rel = 'prefetch';
        document.head.appendChild(prefetcher);
        
        const eventListenerOptions = {
            capture: true,
            passive: true
        }
        document.addEventListener('touchstart', touchstartListener, eventListenerOptions);
        document.addEventListener('mouseover', mouseoverListener, eventListenerOptions)
        
    }
    
}
    

function touchstartListener(event) {
    lastTouchTimestamp = performance.now();
    const linkElement = event.target.closest('a');
    if(!linkElement) {
        return;
    }
    if(!isPreloadable(linkElement)){
        return;
    }

}
function touchAndTouchcancelListener() {
    urlToPreload = undefined;
    stopPreloading();
}
function mouseoverListener(event) {
    if(performance.now() - lastTouchTimestamp < 1100) {
        return;
    }
    const linkElement = event.target.closest('a');
    if(!linkElement) {
        return;
    }
    if(!isPreloadable(linkElement)){
        return;
    }
    linkElement.addEventListener('mouseout', mouseoutListener, {passive: true});
    urlToPreload = linkElement.href;
    mouseOverTimer = setTimeout(() => {
        preload(linkElement.href);
        mouseOverTimer = undefined;
    }, 65)
}
function mouseoutListener(event) {
    if(event.relatedTarget && event.target.closest('a') == event.relatedTarget.closest('a')){
        return;
    }
    if(mouseOverTimer){
        clearTimeout(mouseOverTimer);
        mouseOverTimer = undefined;
    } else {
        urlToPreload = undefined;
        stopPreloading();
    }
}
function isPreloadable(linkElement) {
    if(urlToPreload == linkElement.href) {
        return;
    }
    const urlObject = new URL(linkElement.href);
    if(urlObject.origin !== location.origin) {
        return;
    }
    if(!allowQueryString && urlObject.search && !('instant' in linkElement.dataset)) {
        return;
    }
    if(urlObject.hash && urlObject.pathname + urlObject.search == location.pathname + location.search) {
        return;
    }
    if('noInstant' in linkElement.dataset) {
        return;
    }
    return true;
}
function preload(url) {
    prefetcher.href = url;
}
function stopPreloading() {
    prefetcher.removeAttribute('href');
}