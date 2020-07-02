const counters = document.querySelectorAll('.counter');
const speed = 10; // The lower the slower

counters.forEach(counter => {
    const updateCount = () => {
        const target = +counter.getAttribute('data-target');
        const count = +counter.innerText;

        // Lower inc to slow and higher to slow
        const inc = target / speed;

        // Check if target is reached
        if (count < target) {
            // Add inc to count and output in counter
            if(target <= 1)
            {
                counter.innerText = (count + inc).toFixed(2);
            }
            else{
                counter.innerText = Math.ceil(count + inc);
            }
            // Call function every ms
            setTimeout(updateCount, 30);
        } else {
            counter.innerText = target;
        }
    };

    updateCount();
});

