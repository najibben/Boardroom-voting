

function drawVotesColumn(result) {
          var var_color = '#0040ff';
          var winner = [var_color, var_color, var_color, var_color, var_color, var_color];
          var max = -Infinity, argmax = [];
          for(var i=0; i<result.length; ++i)
            if(result[i] > max) max = result[i], argmax = [i];
            else if(result[i] === max) argmax.push(i);
          for (var y in argmax) {
            winner[argmax[y]] = '#00ff00';
          }

          var scale = [];
          var l = Math.max(...result);
          for (var z = 0; z < l; z++) {
            scale.push(z+1);
          }
          var opc = 0.6;

          var data = google.visualization.arrayToDataTable([
            ['Candidate', 'Votes', { role: 'style' } ],
            ['Alice', result[0], 'color:' + winner[0] + '; opacity:' + opc],
            ['Bob', result[1], 'color:' + winner[1] + '; opacity:' + opc],
            ['Charlie', result[2], 'color:' + winner[2] + '; opacity:' + opc],
          ]);

          var options = {
            title: 'GENERAL RESULTS:',
            hAxis: {
              title: 'CANDIDATES'
            },
            vAxis: {
              title: 'VOTES [ # ]',
              ticks: scale
            },
            legend: { position: 'bottom', maxLines: 3, alignment: 'start' },
            bar: {groupWidth: "90%"},
            chartArea: {
              left: 'auto',
              top:'auto',
              width:'auto',
              height:'auto'
            },
            legend: {position: 'none'},
            format: 'decimal',
            backgroundColor: {
              fill: '#ffffff',
              fillOpacity: 1,
            },
          };

          var chart = new google.visualization.ColumnChart(document.getElementById('chart_div'));
          chart.draw(data, options);
    };
    function drawVotesDonut(result) {
          var data = google.visualization.arrayToDataTable([
            ['Candidate', 'Votes'],
            ['Alice', result[0]],
            ['Bob', result[1]],
            ['Charlie', result[2]]
          ]);

          var options = {
            title: 'GENERAL RESULTS:',
            pieHole: 1,
            chartArea: {width: '100%'},
            is3D: true,
          };

          var chart = new google.visualization.PieChart(document.getElementById('chart_div2'));
          chart.draw(data, options);
    };


$(window).resize(function(){
      drawVotesColumn();
      drawVotesDonut();
    });